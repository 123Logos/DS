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
async def create_jsapi_order(request: Request, current_user: dict = Depends(get_current_user)):
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
                    "pending_coupon_id, pending_coupon_ids FROM orders WHERE order_number=%s FOR UPDATE",
                    (out_trade_no,),
                )
                order_row = cur.fetchone()
                if not order_row:
                    raise HTTPException(status_code=404, detail="order not found")
                if int(order_row['user_id']) != int(current_user['id']):
                    raise HTTPException(403, '无权支付该订单')
                cur.execute('SELECT openid FROM users WHERE id=%s', (current_user['id'],))
                payer = cur.fetchone()
                if not payer or not payer.get('openid') or payer['openid'] != openid:
                    raise HTTPException(403, '支付身份不匹配')
                if order_row.get('status') != 'pending_pay':
                    raise HTTPException(status_code=400, detail="order not in pending_pay state")

                pending_points = Decimal(str(order_row.get('pending_points') or 0))
                if points_to_use is not None and Decimal(str(points_to_use)) != pending_points:
                    raise HTTPException(409, '订单优惠已锁定，请重新创建订单')

                # 重新计算应付金额（分），防止前端传错
                # 使用 original_amount 减去本次 pending 优惠，而不是再次从 total_amount 扣减
                # original_amount is now guaranteed to exist because we selected it above.
                original_amount = Decimal(str(order_row.get('original_amount') or order_row.get('total_amount') or 0))
                stored_pending = Decimal(str(order_row.get('pending_points') or 0))
                stored_coupon_ids = parse_pending_coupon_ids(order_row)

                if payload_coupon_ids and payload_coupon_ids != sorted(stored_coupon_ids):
                    raise HTTPException(409, '订单优惠已锁定，请重新创建订单')
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

                if payable_cents <= 0:
                    raise HTTPException(409, '零元订单应在创建时完成结算')

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
        except Exception:
            logger.error('payment_provider_unavailable')
            raise HTTPException(502, '支付服务暂时不可用') from None

        prepay_id = resp.get('prepay_id') or resp.get('prepayId')
        if not prepay_id:
            logger.error('payment_provider_missing_prepay')
            raise HTTPException(status_code=500, detail="wechat create order failed")

        # 2) 生成前端支付参数（含 paySign）
        pay_params = pay_client.generate_jsapi_pay_params(prepay_id)
        pkg_val = (pay_params.get("package") or "").strip()
        prepay_tail = pkg_val[len("prepay_id=") :] if pkg_val.startswith("prepay_id=") else ""
        if not prepay_tail.strip():
            logger.error('payment_provider_invalid_package')
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
        logger.error('payment_create_failed')
        raise HTTPException(503, '支付创建未完成') from None


async def _verified_notification(request):
    body = await request.body()
    headers = request.headers
    signature = headers.get('Wechatpay-Signature')
    timestamp = headers.get('Wechatpay-Timestamp')
    nonce = headers.get('Wechatpay-Nonce')
    serial = headers.get('Wechatpay-Serial')
    if not all((signature, timestamp, nonce, serial)):
        raise HTTPException(401, 'Missing signature headers')
    if serial != settings.WECHAT_PAY_PUB_KEY_ID:
        raise HTTPException(401, 'Untrusted signing key')
    if not pay_client.verify_signature(signature, timestamp, nonce, body.decode('utf-8')):
        raise HTTPException(401, 'Invalid signature')
    envelope = json.loads(body)
    data = pay_client.decrypt_callback_data(envelope['resource'])
    mchid = data.get('mchid') or data.get('sp_mchid')
    expected = settings.WECHAT_PAY_SP_MCH_ID if data.get('sp_mchid') else settings.WECHAT_PAY_MCH_ID
    if not expected or mchid != expected:
        raise HTTPException(400, 'Merchant mismatch')
    appid = data.get('appid') or data.get('sp_appid')
    if appid and appid != settings.WECHAT_APP_ID:
        raise HTTPException(400, 'Application mismatch')
    return envelope, data


@router.post('/notify', summary='微信支付回调通知')
async def wechat_pay_notify(request: Request):
    try:
        envelope, data = await _verified_notification(request)
        event = envelope.get('event_type')
        if event == 'TRANSACTION.SUCCESS':
            if data.get('trade_state') != 'SUCCESS':
                raise HTTPException(400, 'Invalid transaction state')
            await handle_transaction_success(data)
        elif event == 'APPLYMENT_STATE_CHANGE':
            await handle_applyment_state_change(data)
        else:
            raise HTTPException(400, 'Unsupported event')
        return Response(status_code=204)
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError):
        raise HTTPException(400, 'Invalid notification') from None
    except Exception:
        logger.error('payment_notification_storage_failure')
        raise HTTPException(503, 'Notification not committed') from None


@router.post('/refund-notify', summary='微信退款结果通知')
async def wechat_refund_notify(request: Request):
    from services.refund_service import RefundService
    try:
        envelope, data = await _verified_notification(request)
        if not str(envelope.get('event_type', '')).startswith('REFUND.'):
            raise HTTPException(400, 'Unsupported event')
        RefundService.apply_result(data)
        return Response(status_code=204)
    except HTTPException:
        raise
    except (ValueError, KeyError, TypeError):
        raise HTTPException(400, 'Invalid notification') from None
    except Exception:
        logger.error('refund_notification_storage_failure')
        raise HTTPException(503, 'Notification not committed') from None


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
        logger.error('applyment_notification_failed')
        raise


# api/wechat_pay/routes.py （从 handle_transaction_success 开始）

async def handle_transaction_success(data: dict):
    order_no = data['out_trade_no']
    transaction_id = data['transaction_id']
    amount = data['amount']['total']
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0 or data['amount'].get('currency') != 'CNY':
        raise ValueError('Invalid payment amount')
    if order_no.startswith('OFF'):
        await _handle_offline_pay_success(order_no, transaction_id, amount, data)
    else:
        await _handle_online_pay_success(order_no, transaction_id, amount, data)


async def _handle_offline_pay_success(order_no: str, transaction_id: str, amount: int, data: dict):
    from services.offline_service import OfflineService
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM offline_order WHERE order_no=%s FOR UPDATE', (order_no,))
            order = cur.fetchone()
            if not order or int(order['paid_amount']) != amount:
                raise ValueError('Unknown order or amount mismatch')
            cur.execute('SELECT * FROM payment_events WHERE event_key=%s', ('pay:' + order_no,))
            event = cur.fetchone()
            if event:
                if event['transaction_id'] != transaction_id or event['total_fee'] != amount:
                    raise ValueError('Payment identity conflict')
                conn.commit()
                return
            if order['status'] != 1:
                raise ValueError('Order not payable')
            for cid in parse_offline_coupon_ids(order):
                cur.execute("UPDATE coupons SET status='used',used_at=NOW() WHERE id=%s AND user_id=%s AND status='unused' AND valid_to>=CURDATE()", (cid, order['user_id']))
                if cur.rowcount != 1:
                    raise ValueError('Coupon not usable')
            cur.execute('UPDATE offline_order SET status=2,pay_time=NOW(),transaction_id=%s WHERE id=%s', (transaction_id, order['id']))
            await OfflineService.on_paid(order_no, Decimal(amount)/100,
                Decimal(str(order.get('coupon_discount') or 0))/100, transaction_id, external_conn=conn)
            cur.execute('INSERT INTO payment_events(event_key,order_number,transaction_id,total_fee) VALUES(%s,%s,%s,%s)', ('pay:' + order_no, order_no, transaction_id, amount))
            conn.commit()


async def _handle_online_pay_success(order_no: str, transaction_id: str, amount: int, data: dict):
    from services.finance_service import FinanceService
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM orders WHERE order_number=%s FOR UPDATE', (order_no,))
            order = cur.fetchone()
            if not order or int(Decimal(str(order['total_amount'])) * 100) != amount:
                raise ValueError('Unknown order or amount mismatch')
            cur.execute('SELECT * FROM payment_events WHERE event_key=%s', ('pay:' + order_no,))
            event = cur.fetchone()
            if event:
                if event['transaction_id'] != transaction_id or event['total_fee'] != amount:
                    raise ValueError('Payment identity conflict')
                conn.commit()
                return
            if order['status'] != 'pending_pay':
                cur.execute("INSERT INTO payment_reconciliation_cases(case_key,order_number,transaction_id,total_fee,reason) VALUES(%s,%s,%s,%s,'paid_after_local_close') ON DUPLICATE KEY UPDATE case_key=case_key", ('late:' + transaction_id, order_no, transaction_id, amount))
                conn.commit()
                logger.error('payment_reconciliation_required')
                raise ValueError('Payment quarantined; operator reconciliation required')
            cur.execute('UPDATE orders SET transaction_id=%s WHERE id=%s', (transaction_id, order['id']))
            FinanceService().settle_order(order_no=order_no, user_id=order['user_id'], order_id=order['id'],
                points_to_use=order.get('pending_points') or 0, coupon_discount=order.get('coupon_discount') or 0,
                external_conn=conn)
            cur.execute('INSERT INTO payment_events(event_key,order_number,transaction_id,total_fee) VALUES(%s,%s,%s,%s)', ('pay:' + order_no, order_no, transaction_id, amount))
            conn.commit()

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
    from services.refund_service import RefundService
    payload = await request.json()
    return RefundService.request(payload.get('order_number'), current_user,
        refund_fee=payload.get('refund_fee'), reason=payload.get('reason', ''), refund_request_id=payload.get('refund_request_id'))

# 注册路由函数（原文件末尾已有，保留不变）
def register_wechat_pay_routes(app):
    """
    注册微信支付路由
    """
    # 原生路径：/wechat-pay/*
    app.include_router(router)
    # 兼容路径：/api/wechat-pay/* （微信通知回调当前发往 /api/wechat-pay/notify）
    app.include_router(router, prefix="/api")