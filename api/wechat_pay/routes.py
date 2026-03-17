# api/wechat_pay/routes.py
from fastapi import APIRouter, Request, HTTPException, Response
from core.wx_pay_client import WeChatPayClient
from core.config import ENVIRONMENT, WECHAT_PAY_API_V3_KEY, POINTS_DISCOUNT_RATE
from core.response import success_response
from core.database import get_conn
from services.finance_service import FinanceService
from decimal import Decimal
from services.wechat_applyment_service import WechatApplymentService
from datetime import datetime
import time
import uuid
import json
import logging
import base64
from core.config import settings
import xml.etree.ElementTree as ET  # 用于生成XML响应
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

router = APIRouter(prefix="/wechat-pay", tags=["微信支付"])

logger = logging.getLogger(__name__)
pay_client = WeChatPayClient()


@router.post("/create-order", summary="创建JSAPI订单并返回前端支付参数")
async def create_jsapi_order(request: Request):
    """创建 JSAPI 订单并返回前端调用 `wx.requestPayment`/小程序支付所需参数。
    请求 JSON 应包含：out_trade_no/order_id, total_fee(分), openid, description(可选), coupon_id(可选), points_to_use(可选,分)
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
                    "SELECT id, user_id, status, delivery_way, original_amount, total_amount, pending_points, pending_coupon_id "
                    "FROM orders WHERE order_number=%s",
                    (out_trade_no,)
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
                coupon_amt = Decimal('0')
                # 收集当前 pending 信息
                stored_pending = Decimal(str(order_row.get('pending_points') or 0))
                stored_coupon_id = order_row.get('pending_coupon_id')

                pending_coupon_id = order_row.get('pending_coupon_id')
                # 允许在下单时绑定优惠券（未绑定时才绑定）或更改
                if coupon_id:
                    if pending_coupon_id and pending_coupon_id != coupon_id:
                        raise HTTPException(status_code=409, detail="order already bound to another coupon")
                    target_coupon_id = pending_coupon_id or coupon_id

                    cur.execute(
                        "SELECT id, user_id, amount, status, valid_from, valid_to FROM coupons WHERE id=%s",
                        (target_coupon_id,)
                    )
                    coupon_row = cur.fetchone()
                    if not coupon_row or coupon_row.get('user_id') != order_row.get('user_id'):
                        raise HTTPException(status_code=400, detail="coupon not available for user")
                    if coupon_row.get('status') != 'unused':
                        raise HTTPException(status_code=409, detail="coupon already used")

                    today = datetime.now().date()
                    valid_from = coupon_row.get('valid_from')
                    valid_to = coupon_row.get('valid_to')
                    if valid_from and valid_to and not (valid_from <= today <= valid_to):
                        raise HTTPException(status_code=400, detail="coupon expired")

                    if not pending_coupon_id:
                        cur.execute(
                            "UPDATE orders SET pending_coupon_id=%s WHERE id=%s",
                            (target_coupon_id, order_row['id'])
                        )
                    pending_coupon_id = target_coupon_id

                if pending_coupon_id:
                    cur.execute("SELECT amount, status FROM coupons WHERE id=%s", (pending_coupon_id,))
                    coupon_row = cur.fetchone()
                    if coupon_row:
                        coupon_amt = Decimal(str(coupon_row.get('amount') or 0))
                        if coupon_row.get('status') == 'used':
                            raise HTTPException(status_code=409, detail="coupon already used")

                # 计算应付金额：从 original_amount 扣减本次 pending 优惠
                payable_cents = int(original_amount * Decimal('100'))
                payable_cents -= int(pending_points * Decimal('100'))
                payable_cents -= int(coupon_amt * Decimal('100'))

                # 如果前端修改了积分/券，则同步更新订单行并重新计算 total_amount
                if pending_points != stored_pending or pending_coupon_id != stored_coupon_id:
                    new_total = (original_amount - pending_points - coupon_amt)
                    # points_discount should reflect used points * rate
                    pd = pending_points * POINTS_DISCOUNT_RATE
                    cur.execute(
                        "UPDATE orders SET total_amount=%s, pending_points=%s, pending_coupon_id=%s, points_discount=%s, coupon_discount=%s WHERE id=%s",
                        (new_total, pending_points, pending_coupon_id, pd, coupon_amt, order_row['id'])
                    )
                    total_amount = new_total
                else:
                    total_amount = Decimal(str(order_row.get('total_amount') or 0))

                # ========== 新增：提交事务，确保更新持久化 ==========
                conn.commit()
                # =================================================

                # ==================== 零元订单处理 ====================
                if payable_cents <= 0:
                    logger.info(f"零元订单 {out_trade_no} 无需支付，返回模拟支付参数 (原始金额¥%s, total_amount¥%s)" % (
                    order_row.get('original_amount'), order_row.get('total_amount')))
                    return {
                        "appId": settings.WECHAT_APP_ID,
                        "timeStamp": str(int(time.time())),
                        "nonceStr": uuid.uuid4().hex,
                        "package": "prepay_id=ZERO_ORDER",
                        "signType": "RSA",
                        "paySign": "ZERO_ORDER_SIGN"
                    }
                # ====================================================

                if total_fee_client_int != payable_cents:
                    logger.warning(
                        "订单支付金额校正: client=%s, server=%s, order=%s",
                        total_fee_client, payable_cents, out_trade_no
                    )
                    # 若客户端传入金额更低，视为已应用优惠券/积分后的最终应付，优先采用客户端金额
                    if 0 < total_fee_client_int < payable_cents:
                        logger.info(
                            "使用客户端金额作为应付金额: client=%s, server=%s, order=%s",
                            total_fee_client_int, payable_cents, out_trade_no
                        )
                        payable_cents = total_fee_client_int
                total_fee = payable_cents

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
                    logger.error(f"微信下单返回 HTTP 错误: status={getattr(e.response,'status_code', '')} body={body}")
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

        return {
            "prepay_id": prepay_id,
            "pay_params": pay_params,
            "wechat_raw_response": resp
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

        # 验证签名头
        signature = headers.get("Wechatpay-Signature")
        timestamp = headers.get("Wechatpay-Timestamp")
        nonce = headers.get("Wechatpay-Nonce")
        serial = headers.get("Wechatpay-Serial")

        # 开发绕过：允许在非 production 环境下通过自定义头跳过签名校验（仅用于本地/测试）
        bypass_header = headers.get("X-DEV-BYPASS-VERIFY") or headers.get("X-DEV-BYPASS")
        # 支持基于共享测试令牌的绕过（在 systemd/.env 中设置 TEST_NOTIFY_TOKEN）
        test_token_header = headers.get("X-DEV-TEST-TOKEN")
        test_token_env = None
        try:
            import os

            test_token_env = os.getenv("TEST_NOTIFY_TOKEN")
        except Exception:
            test_token_env = None

        if (bypass_header and ENVIRONMENT != "production") or (
            test_token_header and test_token_env and test_token_header == test_token_env
        ):
            logger.warning("开发模式：绕过回调签名校验（开发头或测试令牌触发）")
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

        # 支持开发调试绕过签名验证（兼容性备用头）
        if headers.get("X-Bypass-Signature", "").lower() == "true" and ENVIRONMENT != "production":
            logger.warning("开发模式：跳过签名验证 (X-Bypass-Signature)")

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

        # 开发绕过：若请求头包含 X-DEV-PLAIN-BODY，则认为 resource 已是明文 JSON（跳过 decrypt）
        plain_header = headers.get("X-DEV-PLAIN-BODY") or headers.get("X-DEV-PLAIN")

        # 检查 resource 是否具备解密所需字段
        required_fields = ("ciphertext", "nonce", "associated_data")
        missing_fields = [f for f in required_fields if f not in resource]
        if missing_fields and not (plain_header and ENVIRONMENT != "production"):
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

        if plain_header and ENVIRONMENT != "production":
            logger.info("开发模式：跳过回调解密，直接使用明文 resource（X-DEV-PLAIN-BODY detected）")
            decrypted_data = resource
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

        # 1. 验签（可选但推荐）
        signature = headers.get("Wechatpay-Signature")
        timestamp = headers.get("Wechatpay-Timestamp")
        nonce = headers.get("Wechatpay-Nonce")
        serial = headers.get("Wechatpay-Serial")
        if not all([signature, timestamp, nonce, serial]):
            logger.warning("退款回调缺少必要的签名头")
            return Response(content="", status_code=200)  # 避免微信重试

        if not pay_client.verify_signature(signature, timestamp, nonce, body.decode()):
            logger.warning("退款回调签名验证失败")
            return Response(content="", status_code=200)

        # 2. 解析 JSON
        data = json.loads(body)
        resource = data.get("resource", {})
        if not resource:
            logger.warning("退款回调缺少 resource 字段")
            return Response(content="", status_code=200)

        # 3. 解密 resource
        decrypted = pay_client.decrypt_callback_data(resource)   # 复用已有方法
        if not decrypted:
            logger.warning("退款回调解密失败")
            return Response(content="", status_code=200)

        # 4. 提取关键信息
        out_refund_no = decrypted.get('out_refund_no')
        refund_status = decrypted.get('refund_status')   # SUCCESS / CHANGE / REFUNDCLOSE
        transaction_id = decrypted.get('transaction_id')

        logger.info(f"退款回调: out_refund_no={out_refund_no}, status={refund_status}")

        if refund_status == 'SUCCESS':
            # ---------- 精确匹配订单号 ----------
            # 方式一：从 out_refund_no 提取（需保证格式 REF{order_number}_timestamp）
            # 提取 order_number = out_refund_no.split('_')[0][3:]
            # 方式二：如果 orders 表有 refund_no 字段，可直接用该字段查询
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 假设 orders 表已添加 refund_no 字段
                    cur.execute(
                        "UPDATE orders SET status='refunded', updated_at=NOW() WHERE refund_no=%s",
                        (out_refund_no,)
                    )
                    if cur.rowcount == 0:
                        # 回退方式：通过模糊匹配
                        order_number = out_refund_no.split('_')[0][3:]
                        cur.execute(
                            "UPDATE orders SET status='refunded', updated_at=NOW() WHERE order_number=%s",
                            (order_number,)
                        )
                    conn.commit()
            logger.info(f"退款成功: out_refund_no={out_refund_no}")
        else:
            logger.warning(f"退款状态异常: {refund_status} - {decrypted}")

        # 微信期望任意 2xx 响应即可，无需特定格式
        return Response(content="", status_code=200)

    except Exception as e:
        logger.error(f"退款回调处理失败: {e}", exc_info=True)
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

    logger.info(f"支付成功: 订单号={out_trade_no}, 微信流水号={transaction_id}, 金额={amount}")

    if out_trade_no.startswith("OFF"):
        await _handle_offline_pay_success(out_trade_no, transaction_id, amount, data)
    else:
        await _handle_online_pay_success(out_trade_no, transaction_id, amount, data)


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
                    "SELECT id, user_id, amount, paid_amount, status, coupon_id, merchant_id, store_name "
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
                    coupon_discount = 0
                    if order["coupon_id"]:
                        cur.execute("SELECT amount FROM coupons WHERE id = %s", (order["coupon_id"],))
                        coupon_row = cur.fetchone()
                        if coupon_row:
                            coupon_discount = int(Decimal(coupon_row["amount"]) * 100)
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
                if order["coupon_id"]:
                    try:
                        fs = FinanceService()
                        fs.use_coupon(
                            coupon_id=order["coupon_id"],
                            user_id=order["user_id"],
                            order_type="normal"
                        )
                        logger.info(f"[offline-pay] 优惠券核销成功: 订单={order_no}, 优惠券={order['coupon_id']}")
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
                await OfflineService.on_paid(
                    order_no=order_no,
                    amount=Decimal(db_total) / 100,
                    coupon_discount=Decimal(order["amount"] - db_total) / 100 if order["coupon_id"] else Decimal(0)
                )

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
                    "pending_points, pending_coupon_id, original_amount "
                    "FROM orders WHERE order_number=%s FOR UPDATE",
                    (order_no,)
                )
                order = cur.fetchone()
                if not order:
                    raise ValueError("订单号不存在")
                if order.get('status') != 'pending_pay':
                    logger.info(f"订单 {order_no} 状态为 {order.get('status')}，已处理，忽略")
                    return

                # ✅ 关键修复：直接使用 total_amount 计算应付金额（单位：分）
                db_total = int(Decimal(order['total_amount']) * 100)

                # 优惠券处理（仅锁定和核销，不再参与金额计算）
                coupon_amt = Decimal('0')
                if order.get('pending_coupon_id'):
                    cur.execute(
                        """SELECT amount, status, valid_to, user_id 
                           FROM coupons 
                           WHERE id = %s 
                           AND status = 'unused' 
                           AND valid_to >= CURDATE()
                           FOR UPDATE""",
                        (order['pending_coupon_id'],)
                    )
                    coupon_row = cur.fetchone()
                    if not coupon_row:
                        logger.error(f"订单 {order_no} 优惠券校验失败: ID={order['pending_coupon_id']}")
                        raise ValueError(f"优惠券无效或已失效: {order['pending_coupon_id']}")
                    if coupon_row['user_id'] != order['user_id']:
                        logger.error(
                            f"订单 {order_no} 优惠券用户不匹配: 券用户={coupon_row['user_id']}, 订单用户={order['user_id']}"
                        )
                        raise ValueError("优惠券不属于当前订单用户")
                    coupon_amt = Decimal(str(coupon_row['amount']))
                    # 标记优惠券已使用
                    cur.execute(
                        "UPDATE coupons SET status='used', used_at=NOW() WHERE id=%s",
                        (order['pending_coupon_id'],)
                    )
                    logger.info(
                        f"订单 {order_no} 优惠券核销成功: ID={order['pending_coupon_id']}, 金额={coupon_amt}"
                    )

                # 微信支付金额与系统应付金额核对
                if amount != db_total:
                    raise ValueError(f"金额不一致 微信{amount}≠系统{db_total}")

                # 记录优惠券抵扣金额到订单表
                cur.execute("""
                    UPDATE orders 
                    SET coupon_discount = %s,
                        original_amount = COALESCE(%s, total_amount)
                    WHERE id = %s
                """, (
                    coupon_amt,
                    order.get('original_amount') or order['total_amount'],
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

                # 更新订单状态
                next_status = "pending_recv" if order.get('delivery_way') == 'pickup' else "pending_ship"
                from api.order.order import OrderManager
                OrderManager.update_status(order_no, next_status, external_conn=conn)

                conn.commit()
        logger.info(f"线上订单支付成功: {order_no}")

    except Exception as e:
        logger.error(f"线上订单支付成功处理失败: {e}", exc_info=True)
        # 异常已由上层捕获，订单状态保持 pending_pay，不会错误更新


# 注册路由函数（原文件末尾已有，保留不变）
def register_wechat_pay_routes(app):
    """
    注册微信支付路由
    """
    # 原生路径：/wechat-pay/*
    app.include_router(router)
    # 兼容路径：/api/wechat-pay/* （微信通知回调当前发往 /api/wechat-pay/notify）
    app.include_router(router, prefix="/api")