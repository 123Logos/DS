# api/wechat_pay/routes.py
from fastapi import APIRouter, Request, HTTPException
from core.wx_pay_client import WeChatPayClient
from core.config import ENVIRONMENT, WECHAT_PAY_API_V3_KEY
from core.response import success_response
from core.database import get_conn
from services.finance_service import FinanceService
from decimal import Decimal
from services.wechat_applyment_service import WechatApplymentService
from datetime import datetime
import json
import logging
import base64
import xml.etree.ElementTree as ET  # 用于生成XML响应
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

router = APIRouter(prefix="/wechat-pay", tags=["微信支付"])

logger = logging.getLogger(__name__)
pay_client = WeChatPayClient()


@router.post("/create-order", summary="创建JSAPI订单并返回前端支付参数")
async def create_jsapi_order(request: Request):
    """创建 JSAPI 订单并返回前端调用 `wx.requestPayment`/小程序支付所需参数。
    请求 JSON 应包含：out_trade_no/order_id, total_fee(分), openid, description(可选)
    """
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON payload")

    out_trade_no = payload.get('out_trade_no') or payload.get('order_id')
    total_fee_client = payload.get('total_fee')  # 分
    openid = payload.get('openid')
    description = payload.get('description', '商品支付')
    coupon_id = payload.get('coupon_id')

    if not out_trade_no or not total_fee_client or not openid:
        raise HTTPException(status_code=400, detail="missing out_trade_no/total_fee/openid")

    try:
        # 幂等校验：确保订单存在且处于待支付状态
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, user_id, status, delivery_way, total_amount, pending_points, pending_coupon_id "
                    "FROM orders WHERE order_number=%s",
                    (out_trade_no,)
                )
                order_row = cur.fetchone()
                if not order_row:
                    raise HTTPException(status_code=404, detail="order not found")
                if order_row.get('status') != 'pending_pay':
                    raise HTTPException(status_code=400, detail="order not in pending_pay state")

                # 重新计算应付金额（分），防止前端传错
                total_amount = Decimal(str(order_row.get('total_amount') or 0))
                pending_points = Decimal(str(order_row.get('pending_points') or 0))
                coupon_amt = Decimal('0')

                pending_coupon_id = order_row.get('pending_coupon_id')
                # 允许在下单时绑定优惠券（未绑定时才绑定）
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

                payable_cents = int(total_amount * Decimal('100'))
                payable_cents -= int(pending_points * Decimal('100'))
                payable_cents -= int(coupon_amt * Decimal('100'))

                if payable_cents <= 0:
                    raise HTTPException(status_code=400, detail="invalid payable amount")

                if int(total_fee_client) != payable_cents:
                    logger.warning(
                        "订单支付金额校正: client=%s, server=%s, order=%s",
                        total_fee_client, payable_cents, out_trade_no
                    )
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
            # 尝试识别 requests.HTTPError 并提取响应体
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
        # 调试：记录收到的原始请求体及长度（repr 格式，便于发现隐藏字符）
        try:
            logger.debug(f"收到原始请求体 ({len(body)} bytes): {body!r}")
            logger.debug(f"请求头 Content-Type: {headers.get('content-type') if 'headers' in locals() else request.headers.get('content-type')}")
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


async def handle_transaction_success(data: dict):
    """处理支付成功回调"""
    try:
        out_trade_no = data.get("out_trade_no")
        transaction_id = data.get("transaction_id")
        amount = data.get("amount", {}).get("total")

        if not out_trade_no:
            logger.error("支付回调缺少out_trade_no")
            return

        logger.info(f"支付成功: 订单号={out_trade_no}, 微信流水号={transaction_id}, 金额={amount}")

        # 支付成功后的业务逻辑：
        # 1) 记录订单信息并加行级锁
        # 2) 校验积分、优惠券适用性（商品类型）与金额
        # 3) 暂存/执行待抵扣：扣积分、核销券、资金结算
        # 4) 更新订单状态，记录日志
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 1) 加锁读取订单、待抵扣信息
                    cur.execute(
                        "SELECT id, user_id, status, delivery_way, total_amount, pending_points, pending_coupon_id "
                        "FROM orders WHERE order_number=%s FOR UPDATE",
                        (out_trade_no,)
                    )
                    order = cur.fetchone()
                    if not order:
                        logger.warning(f"支付回调：未找到订单 {out_trade_no}")
                        return

                    if order.get('status') != 'pending_pay':
                        logger.info(f"支付回调：订单 {out_trade_no} 状态为 {order.get('status')}，已处理，忽略")
                        return

                    order_id = order['id']
                    user_id = order.get('user_id') or 0

                    pending_points = Decimal(str(order.get('pending_points') or 0))
                    pending_coupon_id = order.get('pending_coupon_id')
                    total_amount_db = Decimal(str(order.get('total_amount') or 0))

                    logger.info(
                        "订单基础信息: order_id=%s, user_id=%s, total=¥%s, pending_points=%s, pending_coupon_id=%s",
                        order_id, user_id, total_amount_db, pending_points, pending_coupon_id
                    )

                    # 2) 查询订单商品，用于校验券适用性与会员商品
                    has_member_item = False
                    has_normal_item = False
                    try:
                        cur.execute(
                            """
                            SELECT p.is_member_product, oi.quantity
                            FROM order_items oi
                            JOIN products p ON oi.product_id = p.id
                            WHERE oi.order_id=%s
                            """,
                            (order_id,)
                        )
                        for row in cur.fetchall() or []:
                            if row.get('is_member_product'):
                                has_member_item = True
                            else:
                                has_normal_item = True
                    except Exception as e:
                        logger.debug(f"读取订单商品失败（跳过券适用性校验）: {e}")

                    coupon_amount = Decimal('0')
                    if pending_coupon_id:
                        try:
                            cur.execute(
                                "SELECT id, status, amount, applicable_product_type, valid_from, valid_to FROM coupons WHERE id=%s",
                                (pending_coupon_id,)
                            )
                            coupon_row = cur.fetchone()
                            if not coupon_row:
                                logger.error(f"优惠券不存在: {pending_coupon_id}")
                                return
                            coupon_amount = Decimal(str(coupon_row.get('amount') or 0))

                            # 校验适用商品类型（约定: member/normal/all）
                            ctype = (coupon_row.get('applicable_product_type') or 'all').lower()
                            if ctype == 'member' and has_normal_item:
                                logger.error("优惠券仅限会员商品，但订单包含普通商品，拒绝核销")
                                return
                            if ctype == 'normal' and has_member_item:
                                logger.error("优惠券仅限普通商品，但订单包含会员商品，拒绝核销")
                                return
                            if coupon_row.get('status') and coupon_row['status'] == 'used':
                                logger.error("优惠券已使用，拒绝重复核销")
                                return
                        except Exception as e:
                            logger.error(f"读取/校验优惠券失败: {e}")
                            return

                    # 额外检测：若系统未记录优惠券，但微信回调包含 promotion_detail，则按微信优惠金额入账
                    promo_detail = data.get("promotion_detail") or []
                    promo_cents = 0
                    try:
                        for item in promo_detail:
                            if not item:
                                continue
                            promo_cents += int(item.get("amount", 0) or 0)
                    except Exception:
                        promo_cents = 0

                    # 3) 金额校验（微信实付 vs 系统应付）
                    payable_cents_calc = int(total_amount_db * Decimal('100'))
                    try:
                        payable_cents_calc -= int(pending_points * Decimal('100'))
                    except Exception:
                        payable_cents_calc -= int(pending_points)  # 兜底
                    try:
                        payable_cents_calc -= int(coupon_amount * Decimal('100'))
                    except Exception:
                        payable_cents_calc -= int(coupon_amount)

                    # 若微信存在 promotion_detail 且系统未记录优惠券，则使用微信的优惠金额修正 coupon_amount
                    if promo_cents > 0 and not pending_coupon_id:
                        promo_coupon = Decimal(str(promo_cents)) / Decimal('100')
                        coupon_amount += promo_coupon
                        payable_cents_calc -= promo_cents
                        logger.info(
                            "检测到微信优惠券未在系统记录，按回调优惠金额入账: %s（分）", promo_cents
                        )

                    payable_cents = payable_cents_calc

                    if amount is not None and int(amount) != payable_cents:
                        logger.error(
                            "金额不一致，微信=%s分，系统应收=%s分，继续按微信实收入账处理",
                            amount, payable_cents
                        )
                        # 以微信实收为准，避免阻断后续结算/积分/分账；并将差额视为额外优惠
                        diff_cents = payable_cents - int(amount)
                        if diff_cents > 0:
                            coupon_amount += Decimal(str(diff_cents)) / Decimal('100')
                        payable_cents = int(amount)

                    # amount 单位为分，转换为 Decimal 元（FinanceService 内部可能期望元）
                    pay_amount = None
                    try:
                        if amount is not None:
                            pay_amount = Decimal(str(amount)) / Decimal('100')
                    except Exception:
                        pay_amount = None

                    # 4) 扣积分 / 核销券（真正执行），随后结算与分账
                    try:
                        if pending_points > 0:
                            cur.execute(
                                "UPDATE users SET member_points = member_points - %s WHERE id=%s AND member_points >= %s",
                                (pending_points, user_id, pending_points)
                            )
                            if cur.rowcount == 0:
                                logger.error("积分不足或并发冲突，扣减失败")
                                return

                        if pending_coupon_id:
                            cur.execute(
                                "UPDATE coupons SET status='used', used_at=NOW() WHERE id=%s AND status <> 'used'",
                                (pending_coupon_id,)
                            )
                            if cur.rowcount == 0:
                                logger.error("优惠券未更新，可能已被使用")
                                return

                        fs = FinanceService()
                        fs.settle_order(
                            order_no=out_trade_no,
                            user_id=user_id,
                            order_id=order_id,
                            points_to_use=pending_points,
                            coupon_discount=coupon_amount,
                            external_conn=conn
                        )
                    except Exception as e:
                        logger.exception(f"结算/扣减阶段失败 for order {out_trade_no}: {e}")
                        return


                    # 确保订单已完成分账（防止某些路径未执行分账）——幂等检查
                    try:
                        cur.execute("SELECT COUNT(1) AS c FROM account_flow WHERE remark LIKE %s", (f"订单分账: {out_trade_no}%",))
                        cnt_row = cur.fetchone()
                        cnt = cnt_row['c'] if isinstance(cnt_row, dict) else (cnt_row[0] if cnt_row else 0)
                    except Exception:
                        cnt = 0

                    if not cnt:
                        # 尝试从 orders 读取金额与 is_vip_item
                        try:
                            cur.execute("SELECT total_amount, is_vip_item FROM orders WHERE order_number=%s", (out_trade_no,))
                            oinfo = cur.fetchone()
                            total_amt = Decimal(str(oinfo.get('total_amount'))) if oinfo and oinfo.get('total_amount') is not None else None
                            is_vip = bool(oinfo.get('is_vip_item')) if oinfo else False
                            if total_amt is not None:
                                from services.finance_service import split_order_funds

                                try:
                                    split_order_funds(out_trade_no, total_amt, is_vip, cursor=cur)
                                except Exception as e:
                                    logger.warning(f"尝试执行分账失败: {e}")
                        except Exception as e:
                            logger.debug(f"读取订单金额用于分账失败: {e}")

                    # 尝试把微信的 transaction_id / success_time 写入 orders（如果表存在对应列）
                    try:
                        # 检查 transaction_id 列
                        cur.execute("SHOW COLUMNS FROM orders LIKE 'transaction_id'")
                        if cur.fetchone():
                            cur.execute("UPDATE orders SET transaction_id=%s WHERE id=%s", (transaction_id, order_id))
                        # 检查 pay_time 或 paid_at 列
                        pay_time_val = data.get('success_time') or data.get('time_end')
                        if pay_time_val:
                            cur.execute("SHOW COLUMNS FROM orders LIKE 'pay_time'")
                            if cur.fetchone():
                                # 支持两种时间格式：YYYYMMDDHHMMSS 或 ISO8601
                                if isinstance(pay_time_val, str) and pay_time_val.isdigit():
                                    cur.execute("UPDATE orders SET pay_time=STR_TO_DATE(%s,'%%Y%%m%%d%%H%%i%%s') WHERE id=%s", (pay_time_val, order_id))
                                else:
                                    cur.execute("UPDATE orders SET pay_time=%s WHERE id=%s", (pay_time_val, order_id))
                            else:
                                cur.execute("SHOW COLUMNS FROM orders LIKE 'paid_at'")
                                if cur.fetchone():
                                    if isinstance(pay_time_val, str) and pay_time_val.isdigit():
                                        cur.execute("UPDATE orders SET paid_at=STR_TO_DATE(%s,'%%Y%%m%%d%%H%%i%%s') WHERE id=%s", (pay_time_val, order_id))
                                    else:
                                        cur.execute("UPDATE orders SET paid_at=%s WHERE id=%s", (pay_time_val, order_id))
                    except Exception as e:
                        logger.debug(f"尝试写入交易信息到 orders 表失败: {e}")

                    # 更新订单状态
                    next_status = "pending_recv" if order.get('delivery_way') == 'pickup' else "pending_ship"
                    cur.execute(
                        "UPDATE orders SET status=%s, updated_at=NOW() WHERE id=%s AND status='pending_pay'",
                        (next_status, order_id)
                    )
                    if cur.rowcount == 0:
                        logger.warning(f"订单 {out_trade_no} 状态更新未生效，可能已被并发处理")

                    logger.info(
                        "支付回调处理完成: order=%s, user=%s, pay_amount=%s, points_used=%s, coupon_id=%s, next_status=%s",
                        out_trade_no, user_id, pay_amount, pending_points, pending_coupon_id, next_status
                    )
                    conn.commit()

        except Exception as e:
            logger.exception(f"支付成功业务处理异常: {e}")
            return

    except Exception as e:
        logger.error(f"支付成功回调处理失败: {str(e)}", exc_info=True)


def register_wechat_pay_routes(app):
    """
    注册微信支付路由
    注意：prefix 已在 router 中定义，这里不需要重复
    """
    # 原生路径：/wechat-pay/*
    app.include_router(router)
    # 兼容路径：/api/wechat-pay/* （微信通知回调当前发往 /api/wechat-pay/notify）
    app.include_router(router, prefix="/api")