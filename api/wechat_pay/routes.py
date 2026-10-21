# api/wechat_pay/routes.py
from fastapi import APIRouter, Request, HTTPException, Response, Depends
from core.auth import get_current_user, is_platform_admin
from core.wx_pay_client import WeChatPayClient
from core.config import WECHAT_PAY_API_V3_KEY, POINTS_DISCOUNT_RATE
from core.response import success_response
from core.database import get_conn
from services.finance_service import (
    FinanceService,
    parse_pending_coupon_ids,
    parse_offline_coupon_ids,
    max_coupon_total_yuan,
)
from decimal import Decimal
from services.wechat_applyment_service import WechatApplymentService
from datetime import datetime
import time
import uuid
import json
import logging
import base64
import pymysql
from core.config import settings
from core.payment_amounts import prepay_fee_cents_authoritative
import xml.etree.ElementTree as ET  # 用于生成XML响应
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

router = APIRouter(prefix="/wechat-pay", tags=["微信支付"])

logger = logging.getLogger(__name__)
pay_client = WeChatPayClient()


@router.post("/create-order", summary="创建JSAPI订单并返回前端支付参数")
async def create_jsapi_order(request: Request):
    """创建 JSAPI 订单并返回前端调用 `wx.requestPayment`/小程序支付所需参数。
    请求 JSON：out_trade_no/order_id, total_fee(分，须与服务端应付一致), openid, description(可选)；
    coupon_ids(可选,多张券ID数组) 或 coupon_id(可选,单张)；points_to_use(可选)

    前端调起说明（微信 V3）：
    - 使用返回的 `pay_params` 原样传入 `wx.requestPayment`，且勿用 `undefined` 覆盖 `signType`
      （文档默认 signType 为 MD5，若被覆盖为空会误走 V2 分支，客户端可能报「缺少 total_fee」类提示）。
    - `package` 必须为 `prepay_id=wx...` 且等号后非空；若接口包在 `{ code, data }` 内，请取 `data.pay_params`。
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON payload")

    out_trade_no = payload.get('out_trade_no') or payload.get('order_id')
    total_fee_client = payload.get('total_fee')  # 分（客户端传入，可能已扣除优惠券/积分）
    openid = payload.get('openid')
    description = payload.get('description', '商品支付')
    coupon_id = payload.get('coupon_id')
    raw_coupon_ids = payload.get('coupon_ids')
    if isinstance(raw_coupon_ids, list) and raw_coupon_ids:
        payload_coupon_ids = sorted({int(x) for x in raw_coupon_ids})
    elif coupon_id is not None:
        payload_coupon_ids = [int(coupon_id)]
    else:
        payload_coupon_ids = []
    # ========== 新增：获取积分使用量 ==========
    points_to_use = payload.get('points_to_use')  # 单位：分，可选
    # ======================================

    if not out_trade_no or not total_fee_client or not openid:
        raise HTTPException(status_code=400, detail="missing out_trade_no/total_fee/openid")

    # 统一转为 int，确保单位为分
    try:
        total_fee_client_int = int(total_fee_client)
    except Exception:
        raise HTTPException(status_code=400, detail="invalid total_fee")
    if total_fee_client_int <= 0:
        raise HTTPException(status_code=400, detail="invalid total_fee")

    try:
        # 幂等校验：确保订单存在且处于待支付状态
        with get_conn() as conn:
            with conn.cursor() as cur:
                # select original_amount too; previously omitted which meant
                # order_row.get('original_amount') returned None and we fell back
                # to total_amount (already discounted), causing payable_cents to be
                # computed too low (double-subtracting discounts).
                cur.execute(
                    "SELECT id, user_id, status, delivery_way, original_amount, total_amount, pending_points, "
                    "pending_coupon_id, pending_coupon_ids FROM orders WHERE order_number=%s",
                    (out_trade_no,),
                )
                order_row = cur.fetchone()
                if not order_row:
                    raise HTTPException(status_code=404, detail="order not found")
                if order_row.get('status') != 'pending_pay':
                    raise HTTPException(status_code=400, detail="order not in pending_pay state")

                # ========== 新增：处理积分使用量 ==========
                if points_to_use is not None:
                    points_to_use_dec = Decimal(str(points_to_use))  # 直接作为元
                    # 检查用户积分余额是否足够
                    cur.execute("SELECT member_points FROM users WHERE id=%s", (order_row['user_id'],))
                    user_points_row = cur.fetchone()
                    user_points = Decimal(str(user_points_row['member_points'] or 0)) if user_points_row else Decimal('0')
                    if user_points < points_to_use_dec:
                        raise HTTPException(status_code=400, detail="用户积分余额不足")
                    # 更新订单的 pending_points
                    cur.execute(
                        "UPDATE orders SET pending_points = %s WHERE id=%s",
                        (points_to_use_dec, order_row['id'])
                    )
                    # 更新本地变量，用于后续金额计算
                    pending_points = points_to_use_dec
                else:
                    pending_points = Decimal(str(order_row.get('pending_points') or 0))
                # ======================================

                # 重新计算应付金额（分），防止前端传错
                # 使用 original_amount 减去本次 pending 优惠，而不是再次从 total_amount 扣减
                # original_amount is now guaranteed to exist because we selected it above.
                original_amount = Decimal(str(order_row.get('original_amount') or order_row.get('total_amount') or 0))
                stored_pending = Decimal(str(order_row.get('pending_points') or 0))
                stored_coupon_ids = parse_pending_coupon_ids(order_row)

                if payload_coupon_ids:
                    target_coupon_ids = payload_coupon_ids
                else:
                    target_coupon_ids = list(stored_coupon_ids)

                coupon_amt = Decimal('0')
                for cid in target_coupon_ids:
                    cur.execute(
                        "SELECT id, user_id, amount, status, valid_from, valid_to FROM coupons WHERE id=%s",
                        (cid,),
                    )
                    coupon_row = cur.fetchone()
                    if not coupon_row or coupon_row.get('user_id') != order_row.get('user_id'):
                        raise HTTPException(status_code=400, detail=f"coupon not available: {cid}")
                    if coupon_row.get('status') != 'unused':
                        raise HTTPException(status_code=409, detail="coupon already used")
                    today = datetime.now().date()
                    vf, vt = coupon_row.get('valid_from'), coupon_row.get('valid_to')
                    if vf and vt and not (vf <= today <= vt):
                        raise HTTPException(status_code=400, detail="coupon expired")
                    coupon_amt += Decimal(str(coupon_row.get('amount') or 0))

                pd_yuan = pending_points * POINTS_DISCOUNT_RATE
                pd_cap = min(pd_yuan, original_amount)
                max_c = max_coupon_total_yuan(original_amount, pd_cap)
                if coupon_amt > max_c:
                    raise HTTPException(
                        status_code=400,
                        detail=f"优惠券叠加超过上限{max_c}元（扣减积分抵扣后向上取整到元）",
                    )

                pending_coupon_id = target_coupon_ids[0] if len(target_coupon_ids) == 1 else None
                pending_coupon_ids_json = json.dumps(target_coupon_ids) if target_coupon_ids else None
                points_discount_yuan = pending_points * POINTS_DISCOUNT_RATE
                new_total = original_amount - points_discount_yuan - coupon_amt
                payable_cents = int((new_total * Decimal('100')).quantize(Decimal('1')))
                ids_changed = sorted(target_coupon_ids) != sorted(stored_coupon_ids)

                def _sync_order_pay_fields(charge_yuan: Decimal) -> None:
                    cur.execute(
                        """UPDATE orders SET total_amount=%s, pending_points=%s, pending_coupon_id=%s,
                           pending_coupon_ids=%s, points_discount=%s, coupon_discount=%s WHERE id=%s""",
                        (
                            charge_yuan,
                            pending_points,
                            pending_coupon_id,
                            pending_coupon_ids_json,
                            points_discount_yuan,
                            coupon_amt,
                            order_row['id'],
                        ),
                    )

                # 零元订单：先落库再返回模拟支付
                if payable_cents <= 0:
                    _sync_order_pay_fields(max(new_total, Decimal('0')))
                    conn.commit()
                    logger.info(
                        f"零元订单 {out_trade_no} 无需支付 (原始金额¥{order_row.get('original_amount')})"
                    )
                    return {
                        "appId": settings.WECHAT_APP_ID,
                        "timeStamp": str(int(time.time())),
                        "nonceStr": uuid.uuid4().hex,
                        "package": "prepay_id=ZERO_ORDER",
                        "signType": "RSA",
                        "paySign": "ZERO_ORDER_SIGN",
                    }

                # 应付金额仅以服务端计算为准（禁止采用客户端较小金额，防止少付）
                final_cents = prepay_fee_cents_authoritative(
                    server_payable_cents=payable_cents,
                    client_fee_cents=total_fee_client_int,
                )
                if total_fee_client_int != payable_cents:
                    logger.warning(
                        "订单支付金额与客户端不一致（已以服务端为准）: client=%s, server=%s, order=%s",
                        total_fee_client, payable_cents, out_trade_no,
                    )

                charge_yuan = (Decimal(final_cents) / Decimal(100)).quantize(Decimal('0.01'))
                stored_total = Decimal(str(order_row.get('total_amount') or 0)).quantize(Decimal('0.01'))
                if (
                    pending_points != stored_pending
                    or ids_changed
                    or charge_yuan != stored_total
                ):
                    _sync_order_pay_fields(charge_yuan)

                conn.commit()
                total_fee = final_cents

        # 到这里无需持有连接，调用微信接口
        # 1) 调用微信下单，获取 prepay_id
        try:
            resp = pay_client.create_jsapi_order(
                out_trade_no=str(out_trade_no),
                total_fee=int(total_fee),
                openid=str(openid),
                description=description
            )
        except Exception as e:
            # 错误处理（原始代码保持不变）
            try:
                import requests
                if isinstance(e, requests.exceptions.HTTPError) and hasattr(e, 'response'):
                    body = ''
                    try:
                        body = e.response.text
                    except Exception:
                        body = str(e.response)
                    logger.error(
                        "微信下单返回 HTTP 错误: status=%s",
                        getattr(e.response, "status_code", ""),
                    )
                    try:
                        data = json.loads(body)
                        code = data.get('code')
                        message = data.get('message') or data.get('msg') or ''
                    except Exception:
                        code = None
                        message = body

                    if code == 'INVALID_REQUEST' or '参数与首次请求时不一致' in (message or ''):
                        raise HTTPException(status_code=409, detail=f"微信订单重复且参数不一致: {message}")
                    if 'JSAPI支付必须传openid' in (message or ''):
                        raise HTTPException(status_code=422, detail=f"缺少 openid: {message}")
                    raise HTTPException(status_code=502, detail=f"微信下单失败: {message}")
            except HTTPException:
                raise
            except Exception:
                logger.exception("微信下单异常")
                raise HTTPException(status_code=502, detail=str(e))

        prepay_id = resp.get('prepay_id') or resp.get('prepayId')
        if not prepay_id:
            logger.error(f"下单失败，微信返回: {resp}")
            raise HTTPException(status_code=500, detail="wechat create order failed")

        # 2) 生成前端支付参数（含 paySign）
        pay_params = pay_client.generate_jsapi_pay_params(prepay_id)
        pkg_val = (pay_params.get("package") or "").strip()
        prepay_tail = pkg_val[len("prepay_id=") :] if pkg_val.startswith("prepay_id=") else ""
        if not prepay_tail.strip():
            logger.error("生成的 package 无效(预支付 id 为空): package=%r prepay_id=%r", pkg_val, prepay_id)
            raise HTTPException(status_code=500, detail="payment package invalid (empty prepay_id)")

        return {
            "prepay_id": prepay_id,
            "pay_params": pay_params,
            # 与本次微信下单一致的服务端应付金额（分），供展示/对账；V3 调起支付仍以 pay_params 为准
            "total_fee": int(total_fee),
            "wechat_raw_response": resp,
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("创建JSAPI订单失败")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/notify", summary="微信支付回调通知")
async def wechat_pay_notify(request: Request):
    """
    处理微信支付异步通知
    1. 验证签名
    2. 解密回调数据
    3. 更新订单/进件状态
    4. 返回成功响应
    """
    try:
        body = await request.body()

        # 提前定义 headers（关键修复）
        headers = request.headers

        # 调试日志（现在 headers 已存在，不会报错了）
        try:
            logger.debug(f"收到原始请求体 ({len(body)} bytes): {body!r}")
            logger.debug(f"请求头 Content-Type: {headers.get('content-type', '未知')}")
        except Exception:
            logger.debug("无法记录原始请求体（调试日志）")

        # 检查请求体是否为空（防止JSONDecodeError）
        if not body or len(body.strip()) == 0:
            logger.warning("收到空请求体，返回错误响应")
            return _xml_response("FAIL", "Empty request body")

        headers = request.headers

        # 验证签名头（禁止 HTTP 头绕过；本地联调请使用 WX_MOCK_MODE + 明文 resource，见下方解密分支）
        signature = headers.get("Wechatpay-Signature")
        timestamp = headers.get("Wechatpay-Timestamp")
        nonce = headers.get("Wechatpay-Nonce")
        serial = headers.get("Wechatpay-Serial")

        if pay_client.mock_mode:
            logger.info("【MOCK】微信支付回调：跳过签名校验（由 WX_MOCK_MODE 控制）")
        else:
            if not all([signature, timestamp, nonce, serial]):
                logger.error("缺少必要的回调头信息")
                return _xml_response("FAIL", "Missing callback headers")

            try:
                if not pay_client.verify_signature(signature, timestamp, nonce, body.decode()):
                    logger.error("签名验证失败")
                    return _xml_response("FAIL", "Signature verification failed")
            except Exception as e:
                logger.error(f"签名验证异常: {str(e)}")
                return _xml_response("FAIL", f"Signature error: {str(e)}")

        # 解析回调数据（真实微信通知是JSON，部分测试可能使用XML包装）
        content_type = headers.get("content-type", "")
        if "xml" in content_type:
            import xmltodict  # 需要安装: pip install xmltodict

            data_dict = xmltodict.parse(body)
            data = data_dict.get("xml", {})
            if "resource" in data:
                resource = data["resource"]
                if isinstance(resource, str):
                    data = json.loads(resource)
                else:
                    data = {"resource": resource}
            else:
                data = {"resource": data}
        else:
            data = json.loads(body)

        # 解密回调数据
        resource = data.get("resource", {})
        if not resource:
            logger.error("回调数据中缺少resource字段")
            return _xml_response("FAIL", "Missing resource")

        # 检查 resource 是否具备解密所需字段（非 MOCK 时必须为微信密文包）
        required_fields = ("ciphertext", "nonce", "associated_data")
        missing_fields = [f for f in required_fields if f not in resource]
        mock_plain = pay_client.mock_mode and not (resource.get("ciphertext") or "").strip()
        if missing_fields and not mock_plain:
            logger.error(f"回调 resource 缺少必要字段 {missing_fields}; content={resource}")
            return _xml_response("FAIL", f"Missing resource fields: {','.join(missing_fields)}")

        # 记录 resource 关键字段长度以便排查解密失败
        try:
            logger.info(
                "回调 resource 明细: keys=%s, ciphertext_len=%s, nonce_len=%s, ad_len=%s",
                list(resource.keys()),
                len(resource.get("ciphertext", "")) if isinstance(resource.get("ciphertext"), str) else None,
                len(resource.get("nonce", "")) if isinstance(resource.get("nonce"), str) else None,
                len(resource.get("associated_data", "")) if isinstance(resource.get("associated_data"), str) else None,
            )
        except Exception:
            logger.debug("记录 resource 明细失败", exc_info=True)

        if mock_plain:
            logger.info("【MOCK】跳过回调解密，直接使用明文 resource（需 WX_MOCK_MODE=true）")
            decrypted_data = resource if isinstance(resource, dict) else {}
        else:
            # 按官方示例执行 AESGCM 解密
            try:
                key_bytes = WECHAT_PAY_API_V3_KEY.encode("utf-8")
                if len(key_bytes) not in (16, 24, 32):
                    logger.error("API v3 key 长度无效: %s", len(key_bytes))
                    return _xml_response("FAIL", "Invalid APIv3 key length")

                nonce_bytes = str(resource.get("nonce", "")).encode("utf-8")
                ad_str = resource.get("associated_data", "") or ""
                ad_bytes = ad_str.encode("utf-8") if ad_str else None
                cipher_b64 = resource.get("ciphertext", "")

                # 记录首尾片段便于对比是否被篡改
                try:
                    preview = cipher_b64 if len(cipher_b64) <= 80 else f"{cipher_b64[:30]}...{cipher_b64[-30:]}"
                    logger.info(
                        "解密准备: key_len=%s, nonce_len=%s, ad_len=%s, ct_len=%s, ct_preview=%s",
                        len(key_bytes), len(nonce_bytes), len(ad_bytes) if ad_bytes else 0,
                        len(cipher_b64), preview
                    )
                except Exception:
                    logger.debug("记录解密准备信息失败", exc_info=True)

                cipher_bytes = base64.b64decode(cipher_b64)
                aesgcm = AESGCM(key_bytes)
                plaintext = aesgcm.decrypt(nonce_bytes, cipher_bytes, ad_bytes)
                decrypted_data = json.loads(plaintext.decode("utf-8"))
            except Exception as e:
                logger.error(
                    "回调解密异常(官方示例逻辑): %s; key_len=%s; nonce_len=%s; ad_len=%s; ct_len=%s",
                    str(e),
                    len(WECHAT_PAY_API_V3_KEY.encode("utf-8")) if WECHAT_PAY_API_V3_KEY else None,
                    len(resource.get("nonce", "")) if isinstance(resource.get("nonce", ""), str) else None,
                    len(resource.get("associated_data", "")) if isinstance(resource.get("associated_data", ""), str) else None,
                    len(resource.get("ciphertext", "")) if isinstance(resource.get("ciphertext", ""), str) else None,
                )
                return _xml_response("FAIL", "Decrypt failed")

        # 根据事件类型处理（优先外层 event_type，其次解密后字段，兼容交易通知仅在外层提供 event_type）
        event_type = data.get("event_type") or decrypted_data.get("event_type")

        # 兼容交易通知：若无 event_type，但 trade_state=SUCCESS，则视为 TRANSACTION.SUCCESS
        if not event_type and decrypted_data.get("trade_state") == "SUCCESS":
            event_type = "TRANSACTION.SUCCESS"
        try:
            logger.info(
                "解密后 payload 概览: event_type=%s, keys=%s, out_trade_no=%s, transaction_id=%s",
                event_type,
                list(decrypted_data.keys()),
                decrypted_data.get("out_trade_no"),
                decrypted_data.get("transaction_id"),
            )
        except Exception:
            logger.debug("记录解密后 payload 概览失败", exc_info=True)

        if event_type == "APPLYMENT_STATE_CHANGE":
            await handle_applyment_state_change(decrypted_data)
            return _xml_response("SUCCESS", "OK")
        elif event_type == "TRANSACTION.SUCCESS":
            await handle_transaction_success(decrypted_data)
            return _xml_response("SUCCESS", "OK")
        # ===== 新增：处理微信发货管理相关事件 =====
        elif event_type == "trade_manage_remind_shipping":
            from services.wechat_trade_manage_service import process_trade_manage_remind_shipping

            process_trade_manage_remind_shipping(decrypted_data)
            return _xml_response("SUCCESS", "OK")
        elif event_type == "trade_manage_order_settlement":
            from services.wechat_trade_manage_service import process_trade_manage_order_settlement

            process_trade_manage_order_settlement(decrypted_data)
            return _xml_response("SUCCESS", "OK")
        elif event_type in ("trade_manage_remind_access_api", "wxa_trade_controlled"):
            from services.wechat_trade_manage_service import (
                process_trade_manage_remind_access_api,
                process_wxa_trade_controlled,
            )

            if event_type == "trade_manage_remind_access_api":
                process_trade_manage_remind_access_api(decrypted_data)
            else:
                process_wxa_trade_controlled(decrypted_data)
            return _xml_response("SUCCESS", "OK")
        # ==========================================
        else:
            logger.warning(f"未知的事件类型: {event_type}; payload={decrypted_data}")
            return _xml_response("FAIL", f"Unknown event_type: {event_type}")

    except json.JSONDecodeError as e:
        logger.error(f"JSON解析失败: {str(e)}")
        return _xml_response("FAIL", "Invalid JSON format")
    except Exception as e:
        logger.error(f"微信支付回调处理失败: {str(e)}", exc_info=True)
        return _xml_response("FAIL", str(e))

@router.post("/refund-notify", summary="微信退款结果通知")
async def wechat_refund_notify(request: Request):
    """
    处理微信退款异步通知
    更新订单状态为 refunded，并记录退款结果
    """
    try:
        body = await request.body()
        headers = request.headers
        
        logger.info(
            "【退款回调】收到通知，content_type=%s, has_signature=%s",
            headers.get("content-type"),
            bool(headers.get("Wechatpay-Signature")),
        )

        # 1. 验签（可选但推荐）
        signature = headers.get("Wechatpay-Signature")
        timestamp = headers.get("Wechatpay-Timestamp")
        nonce = headers.get("Wechatpay-Nonce")
        serial = headers.get("Wechatpay-Serial")
        if not all([signature, timestamp, nonce, serial]):
            logger.warning("【退款回调】缺少必要的签名头")
            return Response(content="", status_code=200)

        if not pay_client.verify_signature(signature, timestamp, nonce, body.decode()):
            logger.warning("【退款回调】签名验证失败")
            return Response(content="", status_code=200)

        # 2. 解析 JSON
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            logger.error(f"【退款回调】JSON 解析失败: {e}")
            return Response(content="", status_code=200)
            
        resource = data.get("resource", {})
        if not resource:
            logger.warning("【退款回调】缺少 resource 字段")
            return Response(content="", status_code=200)

        # 3. 解密 resource
        decrypted = pay_client.decrypt_callback_data(resource)
        if not decrypted:
            logger.warning("【退款回调】解密失败")
            return Response(content="", status_code=200)

        # 4. 提取关键信息
        out_refund_no = decrypted.get('out_refund_no')
        refund_status = decrypted.get('refund_status')   # SUCCESS / CHANGE / REFUNDCLOSE / PROCESSING
        transaction_id = decrypted.get('transaction_id')
        refund_id = decrypted.get('refund_id')
        amount = decrypted.get('amount', {})

        logger.info(f"【退款回调】解密数据: out_refund_no={out_refund_no}, status={refund_status}, refund_id={refund_id}, amount={amount}")

        # 🔥 新增：处理不同状态
        if refund_status == 'SUCCESS':
            order_number_to_revoke = None
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 先通过 refund_no 更新
                    cur.execute(
                        "UPDATE orders SET status='refunded', updated_at=NOW() WHERE refund_no=%s AND status='refunding'",
                        (out_refund_no,)
                    )
                    updated_rows = cur.rowcount
                    
                    if updated_rows == 0:
                        # 尝试通过解析 out_refund_no 获取 order_number
                        try:
                            parts = out_refund_no.split('_')
                            if len(parts) >= 2 and parts[0].startswith('REF'):
                                order_number = parts[0][3:]
                                cur.execute(
                                    "UPDATE orders SET status='refunded', updated_at=NOW() WHERE order_number=%s AND status='refunding'",
                                    (order_number,)
                                )
                                updated_rows = cur.rowcount
                                logger.info(f"【退款回调】通过解析 order_number 更新: {order_number}, 影响行数: {updated_rows}")
                                if updated_rows > 0:
                                    order_number_to_revoke = order_number
                        except Exception as e:
                            logger.error(f"【退款回调】解析 order_number 失败: {e}")
                    else:
                        # 获取被更新的订单号，用于后续回退
                        cur.execute("SELECT order_number FROM orders WHERE refund_no=%s", (out_refund_no,))
                        row = cur.fetchone()
                        if row:
                            order_number_to_revoke = row['order_number']
                    
                    if updated_rows > 0 and order_number_to_revoke:
                        # ✅ 在同一个事务中调用回退方法（复用当前游标）
                        try:
                            from services.finance_service import FinanceService
                            FinanceService.revoke_order_discounts(order_number_to_revoke, external_cur=cur)
                            logger.info(f"【退款回调】积分/优惠券回退成功: {order_number_to_revoke}")
                        except Exception as e:
                            logger.error(f"【退款回调】回退积分/优惠券失败，事务将回滚: {e}", exc_info=True)
                            # 抛出异常，导致外层事务回滚，订单状态保持 refunding
                            raise
                    
                    if updated_rows > 0:
                        conn.commit()
                        logger.info(f"【退款回调】✅ 退款成功并完成积分/优惠券回退: out_refund_no={out_refund_no}")
                    else:
                        logger.warning(f"【退款回调】⚠️ 未找到匹配的退款中订单: out_refund_no={out_refund_no}")
                        
        elif refund_status == 'PROCESSING':
            logger.info(f"【退款回调】退款处理中: out_refund_no={out_refund_no}")
            # 保持 refunding 状态，等待下一次回调
            
        elif refund_status == 'CHANGE':
            logger.warning(f"【退款回调】退款异常，需要人工处理: out_refund_no={out_refund_no}, detail={decrypted}")
            # 可以发送告警通知管理员
            
        elif refund_status == 'REFUNDCLOSE':
            logger.warning(f"【退款回调】退款关闭: out_refund_no={out_refund_no}")
            # 更新订单状态回退到之前状态（如 completed）
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE orders SET status='completed', updated_at=NOW() WHERE refund_no=%s AND status='refunding'",
                        (out_refund_no,)
                    )
                    conn.commit()
        else:
            logger.warning(f"【退款回调】未知状态: {refund_status} - {decrypted}")

        # 微信期望任意 2xx 响应
        return Response(content="", status_code=200)

    except Exception as e:
        logger.error(f"【退款回调】处理失败: {e}", exc_info=True)
        # 返回 200 避免微信重试（但记录日志人工处理）
        return Response(content="", status_code=200)

def _xml_response(code: str, message: str) -> str:
    """
    生成微信支付回调要求的XML格式响应
    微信要求返回格式：
    <xml>
        <return_code><![CDATA[SUCCESS/FAIL]]></return_code>
        <return_msg><![CDATA[OK/错误信息]]></return_msg>
    </xml>
    """
    return f"""<xml>
<return_code><![CDATA[{code}]]></return_code>
<return_msg><![CDATA[{message}]]></return_msg>
</xml>"""


async def handle_applyment_state_change(data: dict):
    """处理进件状态变更回调"""
    try:
        applyment_id = data.get("applyment_id")
        state = data.get("applyment_state")

        if not applyment_id or not state:
            logger.error("进件回调缺少必要字段")
            return

        service = WechatApplymentService()
        await service.handle_applyment_state_change(
            applyment_id,
            state,
            {
                "state_msg": data.get("state_msg"),
                "sub_mchid": data.get("sub_mchid"),
            },
        )
        logger.info(f"进件状态更新成功: {applyment_id} -> {state}")
    except Exception as e:
        logger.error(f"进件状态处理失败: {str(e)}", exc_info=True)


# api/wechat_pay/routes.py （从 handle_transaction_success 开始）

async def handle_transaction_success(data: dict):
    out_trade_no = data.get("out_trade_no")
    transaction_id = data.get("transaction_id")
    amount = data.get("amount", {}).get("total")

    if not out_trade_no:
        logger.error("支付回调缺少 out_trade_no")
        return

    # 与小程序「发货管理」列表对齐：须与公众平台绑定的 appid、mchid 一致（便于排查搜不到单）
    logger.info(
        "支付成功: 订单号=%s, 微信流水号=%s, 金额=%s, appid=%s, mchid=%s, sub_mchid=%s",
        out_trade_no,
        transaction_id,
        amount,
        data.get("appid"),
        data.get("mchid"),
        data.get("sub_mchid"),
    )

    try:
        if out_trade_no.startswith("OFF"):
            await _handle_offline_pay_success(out_trade_no, transaction_id, amount, data)
        else:
            await _handle_online_pay_success(out_trade_no, transaction_id, amount, data)
    except ValueError as e:
        # 业务错误：订单不存在、金额不一致等，记录但返回成功（避免微信重试）
        logger.error(f"支付成功处理失败（业务错误）: {e}", exc_info=True)
        # 可选：将异常记录到专门的表供人工对账
    except Exception as e:
        # 临时性错误：数据库连接、微信API调用失败等，继续抛出让微信重试
        logger.error(f"支付成功处理发生未知异常: {e}", exc_info=True)
        raise


async def _handle_offline_pay_success(order_no: str, transaction_id: str, amount: int, data: dict):
    from decimal import Decimal
    from services.offline_service import OfflineService
    from services.finance_service import FinanceService
    from core.database import get_conn
    import pymysql

    try:
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 查询并锁定订单
                cur.execute(
                    "SELECT id, user_id, amount, paid_amount, status, coupon_id, coupon_ids, coupon_discount, merchant_id, store_name "
                    "FROM offline_order WHERE order_no = %s FOR UPDATE",
                    (order_no,)
                )
                order = cur.fetchone()

                if not order:
                    logger.error(f"[offline-pay] 订单不存在: {order_no}")
                    raise ValueError(f"订单不存在: {order_no}")

                if order["status"] != 1:
                    logger.info(f"[offline-pay] 订单已处理: {order_no}, 状态={order['status']}")
                    return

                # 金额核对（增强版）
                db_total = order.get("paid_amount")
                if db_total is None or db_total == 0:
                    logger.warning(f"[offline-pay] 订单 {order_no} paid_amount 为0或None，尝试从优惠券重新计算")
                    coupon_discount = int(order.get("coupon_discount") or 0)
                    if coupon_discount <= 0:
                        coupon_discount = 0
                        cids = parse_offline_coupon_ids(order)
                        if cids:
                            ph = ",".join(["%s"] * len(cids))
                            cur.execute(
                                f"SELECT id, amount FROM coupons WHERE id IN ({ph})",
                                tuple(cids),
                            )
                            rows = cur.fetchall() or []
                            by_id = {int(r["id"]): r for r in rows}
                            for cid in cids:
                                r = by_id.get(int(cid))
                                if not r:
                                    continue
                                coupon_discount += int(Decimal(r["amount"]) * 100)
                    expected_paid = order["amount"] - coupon_discount
                    if expected_paid < 0:
                        expected_paid = 0
                    if amount != expected_paid:
                        logger.error(f"[offline-pay] 重新计算后金额仍不一致: 微信{amount}≠预期{expected_paid}")
                        raise ValueError(f"金额不一致")
                    db_total = expected_paid
                    # 更新订单的 paid_amount 为正确值
                    cur.execute("UPDATE offline_order SET paid_amount = %s WHERE id = %s", (db_total, order["id"]))
                    logger.info(f"[offline-pay] 已修复订单 {order_no} paid_amount 为 {db_total}")
                else:
                    if amount != db_total:
                        logger.error(f"[offline-pay] 金额不一致: 微信{amount}≠系统{db_total}")
                        raise ValueError(f"金额不一致: 微信{amount}≠系统{db_total}")

                # 核销优惠券（如果有）
                offline_cids = parse_offline_coupon_ids(order)
                if offline_cids:
                    try:
                        fs = FinanceService()
                        for cid in offline_cids:
                            fs.use_coupon(
                                coupon_id=int(cid),
                                user_id=order["user_id"],
                                order_type="normal"
                            )
                        logger.info(f"[offline-pay] 优惠券核销成功: 订单={order_no}, 优惠券={offline_cids}")
                    except Exception as e:
                        logger.error(f"[offline-pay] 优惠券核销失败（需人工处理）: 订单={order_no}, 错误={e}")

                # 更新订单状态
                cur.execute(
                    """
                    UPDATE offline_order
                    SET status = 2,
                        pay_time = NOW(),
                        transaction_id = %s,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (transaction_id, order["id"])
                )

                # 资金分账
                tw = await OfflineService.on_paid(
                    order_no=order_no,
                    amount=Decimal(db_total) / 100,
                    coupon_discount=Decimal(order["amount"] - db_total) / 100 if offline_cids else Decimal(0),
                    transaction_id=transaction_id,
                )
                if tw:
                    logger.warning(f"[offline-pay] 商家转账未成功（已分账） order={order_no}: {tw}")

                conn.commit()
                logger.info(f"[offline-pay] 线下订单支付成功: {order_no}")

    except Exception as e:
        logger.error(f"[offline-pay] 处理失败: {e}", exc_info=True)
        raise


async def _handle_online_pay_success(order_no: str, transaction_id: str, amount: int, data: dict):
    """处理线上订单支付成功"""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 查询订单信息
                cur.execute(
                    "SELECT id, user_id, total_amount, status, delivery_way, "
                    "pending_points, pending_coupon_id, pending_coupon_ids, original_amount, "
                    "coupon_discount, points_discount "
                    "FROM orders WHERE order_number=%s FOR UPDATE",
                    (order_no,),
                )
                order = cur.fetchone()
                if not order:
                    raise ValueError("订单号不存在")

                tid_existing = order.get("transaction_id")
                if tid_existing:
                    if str(tid_existing) != str(transaction_id):
                        raise ValueError(
                            f"订单已绑定其他微信交易号: 已有={tid_existing}, 回调={transaction_id}"
                        )
                    if order.get("status") != "pending_pay":
                        logger.info(
                            "微信支付回调幂等: 订单=%s 已处理 status=%s transaction_id=%s",
                            order_no,
                            order.get("status"),
                            transaction_id,
                        )
                        return

                if order.get('status') != 'pending_pay':
                    logger.info(f"订单 {order_no} 状态为 {order.get('status')}，已处理，忽略")
                    return

                db_total = int((Decimal(str(order['total_amount'] or 0)) * 100).quantize(Decimal('1')))

                coupon_amt = Decimal('0')
                coupon_id_list = parse_pending_coupon_ids(order)
                if coupon_id_list:
                    for cid in coupon_id_list:
                        cur.execute(
                            """SELECT id, amount, status, valid_to, user_id 
                               FROM coupons 
                               WHERE id = %s 
                               FOR UPDATE""",
                            (cid,),
                        )
                        coupon_row = cur.fetchone()
                        if not coupon_row or coupon_row['status'] != 'unused' or coupon_row[
                            'valid_to'] < datetime.now().date():
                            if order.get('status') == 'pending_pay':
                                logger.error(
                                    f"订单 {order_no} 优惠券 {cid} 状态异常 "
                                    f"(status={coupon_row['status'] if coupon_row else 'not found'})，需人工介入"
                                )
                            return
                        if coupon_row['user_id'] != order['user_id']:
                            logger.error(f"订单 {order_no} 优惠券 {cid} 用户不匹配")
                            return
                        coupon_amt += Decimal(str(coupon_row['amount']))

                    orig = Decimal(str(order.get('original_amount') or 0))
                    pp = Decimal(str(order.get('pending_points') or 0))
                    pd = pp * POINTS_DISCOUNT_RATE
                    if pd > orig:
                        pd = orig
                    max_c = max_coupon_total_yuan(orig, pd)
                    if coupon_amt > max_c:
                        raise ValueError(f"优惠券叠加超过上限{max_c}")

                    for cid in coupon_id_list:
                        cur.execute(
                            "UPDATE coupons SET status='used', used_at=NOW() WHERE id=%s AND status='unused'",
                            (cid,),
                        )
                        if cur.rowcount == 0:
                            logger.warning(f"订单 {order_no} 优惠券 {cid} 核销影响行数为0")
                            if order.get('status') == 'pending_pay':
                                logger.error(f"订单 {order_no} 优惠券核销失败，需人工介入")
                            return
                else:
                    coupon_amt = Decimal(str(order.get("coupon_discount") or 0))
                    if coupon_amt > 0:
                        logger.warning(
                            "订单 %s 无 pending_coupon_ids 但存在 coupon_discount=%s，跳过核销，按落库券额结算",
                            order_no,
                            coupon_amt,
                        )

                # 微信支付金额与系统应付金额核对
                if amount != db_total:
                    raise ValueError(f"金额不一致 微信{amount}≠系统{db_total}")

                # 记录优惠券抵扣金额到订单表
                # 记录优惠券抵扣金额和交易流水号到订单表
                cur.execute("""
                    UPDATE orders 
                    SET coupon_discount = %s,
                        original_amount = COALESCE(%s, total_amount),
                        transaction_id = %s
                    WHERE id = %s
                """, (
                    coupon_amt,
                    order.get('original_amount') or order['total_amount'],
                    transaction_id,
                    order['id']
                ))

                # 资金结算（积分抵扣在 settle_order 内部处理）
                from services.finance_service import FinanceService
                fs = FinanceService()
                fs.settle_order(
                    order_no=order_no,
                    user_id=order['user_id'],
                    order_id=order['id'],
                    points_to_use=order.get('pending_points') or 0,
                    coupon_discount=coupon_amt,
                    external_conn=conn
                )

                # 终端状态已由 settle_order/_settle_order_internal 写入（全虚拟→completed，否则 pending_ship/pending_recv）
                # 切勿在此处再次 update_status，否则会覆盖虚拟订单的 completed，造成「已到账仍显示待收货」等问题

                try:
                    conn.commit()
                except pymysql.err.IntegrityError as ie:
                    conn.rollback()
                    logger.error(
                        "线上支付回调提交失败（唯一约束，常见为 transaction_id 与其它订单冲突）: order=%s err=%s",
                        order_no,
                        ie,
                    )
                    raise ValueError("transaction_id 唯一约束冲突，需人工对账") from ie
        logger.info(f"线上订单支付成功: {order_no}")
        if order.get("delivery_way") == "pickup":
            import asyncio

            from services.wechat_shipping_v2_service import upload_pickup_shipping_to_wechat

            async def _pickup_upload_bg():
                try:
                    await asyncio.to_thread(upload_pickup_shipping_to_wechat, order_no, transaction_id)
                except Exception as ex:
                    logger.error(
                        "自提微信发货后台任务异常 order=%s: %s",
                        order_no,
                        ex,
                        exc_info=True,
                    )

            try:
                asyncio.create_task(_pickup_upload_bg())
            except RuntimeError:
                upload_pickup_shipping_to_wechat(order_no, transaction_id)

    except Exception as e:
        logger.error(f"线上订单支付成功处理失败: {e}", exc_info=True)
        # 异常已由上层捕获，订单状态保持 pending_pay，不会错误更新

@router.post("/refund", summary="申请订单退款")
async def create_refund(
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    """
    主动申请微信退款（支持线上订单）
    请求体: {
        "order_number": "订单号",
        "refund_fee": 100,  # 退款金额（分），可选，默认全额
        "reason": "退款原因"  # 可选
    }
    """
    try:
        payload = await request.json()
        order_number = payload.get("order_number")
        refund_fee = payload.get("refund_fee")  # 分
        reason = payload.get("reason", "用户申请退款")
        
        if not order_number:
            raise HTTPException(400, "缺少订单号")
        
        from core.database import get_conn
        import pymysql
        from decimal import Decimal
        
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 查询订单
                cur.execute(
                    """                    SELECT id, order_number, transaction_id, total_amount, status, user_id, refund_no
                    FROM orders WHERE order_number=%s FOR UPDATE""",
                    (order_number,)
                )
                order = cur.fetchone()
                
                if not order:
                    raise HTTPException(404, "订单不存在")
                if not is_platform_admin(current_user) and int(order["user_id"]) != int(current_user["id"]):
                    raise HTTPException(403, "无权操作该订单")
                if order["status"] == "refunding":
                    return {
                        "success": True,
                        "refund_no": order.get("refund_no"),
                        "message": "退款已在处理中",
                    }
                if order["status"] == "refunded":
                    raise HTTPException(409, "该订单已完成退款")
                
                if order["status"] not in ["pending_ship", "pending_recv", "completed"]:
                    raise HTTPException(400, f"订单状态 {order['status']} 不允许退款")
                
                transaction_id = order.get("transaction_id")
                if not transaction_id:
                    raise HTTPException(400, "订单未支付或缺少微信交易号")
                
                # 计算退款金额（分）
                total_fee = int((Decimal(str(order["total_amount"])) * 100).quantize(Decimal("1")))
                if refund_fee:
                    refund_fee = int(refund_fee)
                    if refund_fee > total_fee:
                        raise HTTPException(400, "退款金额不能大于订单金额")
                else:
                    refund_fee = total_fee
                
                # 生成退款单号
                import time
                out_refund_no = f"REF{order_number}_{int(time.time())}"
                
                # 调用微信退款
                logger.info(f"[Refund] 发起退款: order={order_number}, tx={transaction_id}, refund_fee={refund_fee}")
                result = pay_client.refund(
                    transaction_id=transaction_id,
                    out_refund_no=out_refund_no,
                    total_fee=total_fee,
                    refund_fee=refund_fee,
                    notify_url=f"{settings.WECHAT_PAY_NOTIFY_URL}/refund-notify" if settings.WECHAT_PAY_NOTIFY_URL else None
                )
                
                logger.info(f"[Refund] 微信退款申请结果: {result}")
                
                # 更新订单状态为退款中
                cur.execute(
                    "UPDATE orders SET status='refunding', refund_no=%s, updated_at=NOW() "
                    "WHERE id=%s AND status IN ('pending_ship','pending_recv','completed')",
                    (out_refund_no, order["id"])
                )
                if cur.rowcount != 1:
                    conn.rollback()
                    raise HTTPException(409, "订单状态已变化，请勿重复申请退款")
                conn.commit()
                
                return {
                    "success": True,
                    "refund_no": out_refund_no,
                    "wechat_result": result,
                    "message": "退款申请已提交，等待微信处理"
                }
                
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"[Refund] 退款申请失败: {e}", exc_info=True)
        raise HTTPException(500, f"退款申请失败: {str(e)}")

# 注册路由函数（原文件末尾已有，保留不变）
def register_wechat_pay_routes(app):
    """
    注册微信支付路由
    """
    # 原生路径：/wechat-pay/*
    app.include_router(router)
    # 兼容路径：/api/wechat-pay/* （微信通知回调当前发往 /api/wechat-pay/notify）
    app.include_router(router, prefix="/api")