# services/notify_service.py
from __future__ import annotations
from typing import TYPE_CHECKING, Union

import pymysql  # 补充 Union
import asyncio  # 添加导入

if TYPE_CHECKING:
    from wechatpayv3 import WeChatPay
    from core.config import Settings

# 下面是你原来的 import 列表
import httpx
from decimal import Decimal
from datetime import datetime
from pathlib import Path
from core.config import settings
from core.logging import get_logger
from core.database import get_conn

# 给全局变量加类型标注（仅静态检查用）
wxpay: WeChatPay | None
settings: Settings

logger = get_logger(__name__)

# ----------- 全局 wxpay 实例 ----------
if not settings.wx_mock_mode_bool:  # ✅ 修改为布尔属性
    from wechatpayv3 import WeChatPay, WeChatPayType

    # 加载商户私钥（字符串）
    _private_key = Path(settings.WECHAT_PAY_API_KEY_PATH).read_text(encoding="utf-8")

    # 加载微信支付平台公钥（字符串，不是对象！）
    public_key_str = None
    if settings.WECHAT_PAY_PUBLIC_KEY_PATH and Path(settings.WECHAT_PAY_PUBLIC_KEY_PATH).exists():
        public_key_str = Path(settings.WECHAT_PAY_PUBLIC_KEY_PATH).read_text(encoding="utf-8")

    # 初始化微信支付客户端
    wxpay = WeChatPay(
        wechatpay_type=WeChatPayType.MINIPROG,
        mchid=settings.WECHAT_PAY_MCH_ID,
        private_key=_private_key,
        cert_serial_no=settings.WECHAT_CERT_SERIAL_NO,
        apiv3_key=settings.WECHAT_PAY_API_V3_KEY,
        appid=settings.WECHAT_APP_ID,
        public_key=public_key_str,  # 传入字符串，不是对象
        public_key_id=settings.WECHAT_PAY_PUB_KEY_ID,
        # user_agent="github.com/wechatpay-apiv3/wechatpay-python"
    )
else:
    wxpay = None


# 2. 给用户微信“零钱到账”通知
async def _transfer_to_user(openid: str, amount: Decimal, desc: str) -> str:
    if settings.wx_mock_mode_bool:
        logger.info(f"[MOCK] 转账 {amount:.2f} 元至 {openid}（描述：{desc}）")
        return "mock_batch_id"

    if amount <= 0:
        logger.info(f"[Notify] 转账金额为0，跳过")
        return "zero_amount"

    amount_int = int(amount * 100)
    req = {
        "appid": settings.WECHAT_APP_ID,
        "out_batch_no": f"MER{int(datetime.now().timestamp())}",
        "batch_name": "线下收银到账",
        "batch_remark": desc,
        "total_amount": amount_int,
        "total_num": 1,
        "transfer_detail_list": [{
            "out_detail_no": f"USER{int(datetime.now().timestamp())}",
            "transfer_amount": amount_int,
            "transfer_remark": desc,
            "openid": openid
        }]
    }
    try:
        # 将同步的 transfer_batch 调用放到线程池中执行
        status_code, resp_data = await asyncio.to_thread(wxpay.transfer_batch, **req)
        if status_code == 200:
            logger.info(f"[WeChat] 转账成功: {resp_data}")
            return resp_data.get("batch_id", "")
        else:
            logger.error(f"[WeChat] 转账失败: {resp_data}")
            raise Exception(f"转账失败: {resp_data}")
    except Exception as e:
        logger.error(f"[WeChat] 转账异常: {e}")
        raise


# 3. 给商户微信下发「模板消息」
async def _notify_template(openid: str, order_no: str, amount: Decimal):
    if settings.wx_mock_mode_bool:  # ✅ 使用布尔属性
        logger.info(f"[MOCK] 模板消息：openid={openid} 订单={order_no} 金额={amount:.2f}")
        return
    """
    公众号模板消息 / 小程序订阅消息
    以公众号为例，模板 ID 需提前在后台配置
    """
    data = {
        "touser": openid,
        "template_id": settings.WECHAT_TMPL_MERCHANT_INCOME,
        "url": f"{settings.HOST}/merchant/statement",
        "data": {
            "first": {"value": "您有一笔新收款", "color": "#173177"},
            "keyword1": {"value": order_no, "color": "#173177"},
            "keyword2": {"value": f"¥{amount:.2f}", "color": "#173177"},
            "keyword3": {"value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "color": "#173177"},
            "remark": {"value": "款项已转入您的微信零钱，请查收", "color": "#173177"}
        }
    }
    url = f"https://api.weixin.qq.com/cgi-bin/message/template/send?access_token={await _get_access_token()}"
    async with httpx.AsyncClient() as client:
        r = await client.post(url, json=data)
        r.raise_for_status()
        logger.info(f"[WeChat] 模板消息发送成功: {r.json()}")


# 4. 获取公众号/小程序 access_token（缓存 7000s）
async def _get_access_token() -> str:
    # 简单内存缓存，生产环境可换 Redis
    import time
    now = int(time.time())
    if not hasattr(_get_access_token, "_cache") or now - _get_access_token._cache[1] > 7000:
        url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={settings.WECHAT_APP_ID}&secret={settings.WECHAT_APP_SECRET}"
        async with httpx.AsyncClient() as client:
            r = await client.get(url)
            r.raise_for_status()
            token = r.json()["access_token"]
            _get_access_token._cache = (token, now)
    return _get_access_token._cache[0]


# 5. 对外唯一入口：微信到账通知
async def notify_merchant(merchant_id: int, order_no: str, amount: int) -> None:
    """
    到账推送 = 真正转账到商户微信零钱 + 下发模板消息
    amount: 单位分
    """
    amount_dec = Decimal(amount) / 100
    logger.info(f"[Notify] 商家{merchant_id} 订单{order_no} 到账{amount_dec:.2f}元")

    # 查商户 openid（需提前在 users 表保存）
    with get_conn() as conn:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("SELECT openid FROM users WHERE id=%s", (merchant_id,))
            row = cur.fetchone()
            if not row or not row["openid"]:
                logger.warning(f"商家{merchant_id} 未绑定微信 openid，跳过微信到账")
                return

    openid = row["openid"]
    # 1. 真正转账
    await _transfer_to_user(openid, amount_dec, f"线下订单{order_no}收款")
    # 2. 模板消息
    await _notify_template(openid, order_no, amount_dec)


# ====================== 支付回调（统一下单） ======================
async def handle_pay_notify(raw_body: Union[bytes, str]) -> str:
    """
    微信 V3 支付异步通知
    支持：线上订单（orders表）和线下订单（offline_order表）
    """
    try:
        # 1. 验签 & 解密
        data = wxpay.parse_notify(raw_body)
        logger.info(f"[pay-notify] 微信通知内容: {data}")
        out_trade_no = data["out_trade_no"]
        wx_total = int(data["amount"]["total"])  # 分

        # 2. 判断订单类型（线下订单以 OFF 开头）
        if out_trade_no.startswith("OFF"):
            # ==================== 线下订单处理逻辑 ====================
            return await _handle_offline_pay_notify(out_trade_no, wx_total, data)
        else:
            # ==================== 线上订单处理逻辑（原有代码） ====================
            return await _handle_online_pay_notify(out_trade_no, wx_total, data)

    except Exception as e:
        logger.error(f"[pay-notify] 处理失败: {e}", exc_info=True)
        return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"


async def _handle_offline_pay_notify(order_no: str, wx_total: int, data: dict) -> str:
    from decimal import Decimal
    """
    处理线下收银台订单支付回调
    """
    try:
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 0. 打印调试信息：订单号、长度、当前数据库
                cur.execute("SELECT DATABASE()")
                db_name = cur.fetchone()['DATABASE()']
                logger.info(f"[offline-pay] 收到回调，订单号: '{order_no}', 长度: {len(order_no)}, 数据库: {db_name}")

                # 1. 查询线下订单并锁定
                cur.execute(
                    """
                    SELECT id, user_id, amount, paid_amount, status, 
                           coupon_id, merchant_id, store_name
                    FROM offline_order
                    WHERE order_no=%s FOR UPDATE
                    """,
                    (order_no,)
                )
                order = cur.fetchone()

                if not order:
                    logger.error(f"[offline-pay] 订单不存在: {order_no}")
                    # ✅ 修改为 FAIL，让微信重试
                    return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"

                # 2. 幂等检查：已处理过直接返回成功
                if order["status"] != 1:  # 1=待支付
                    logger.info(f"[offline-pay] 订单已处理: {order_no}, 状态={order['status']}")
                    return "<xml><return_code><![CDATA[SUCCESS]]></return_code></xml>"

                # 3. 金额核对
                db_total = int(Decimal(order["paid_amount"]) * 100) if order["paid_amount"] is not None else int(
                    Decimal(order["amount"]) * 100)

                if wx_total != db_total:
                    logger.error(f"[offline-pay] 金额不一致: 微信{wx_total}≠系统{db_total}")
                    return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"

                # 4. 核销优惠券（关键步骤）
                if order["coupon_id"]:
                    try:
                        from services.finance_service import FinanceService
                        fs = FinanceService()
                        # 线下订单类型为 normal
                        fs.use_coupon(
                            coupon_id=order["coupon_id"],
                            user_id=order["user_id"],
                            order_type="normal"
                        )
                        logger.info(f"[offline-pay] 优惠券核销成功: 订单={order_no}, 优惠券={order['coupon_id']}")
                    except Exception as e:
                        # 优惠券核销失败不应影响订单状态，记录错误人工处理
                        logger.error(f"[offline-pay] 优惠券核销失败（需人工处理）: 订单={order_no}, 错误={e}")
                        # 可以在这里发送告警通知管理员

                # 5. 更新订单状态为已支付（status=2）
                cur.execute(
                    """
                    UPDATE offline_order
                    SET status = 2, 
                        pay_time = NOW(), 
                        transaction_id = %s,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (data.get("transaction_id", ""), order["id"])
                )

                # 6. 资金分账：平台抽成各池 + 商户转账通知
                try:
                    from services.offline_service import OfflineService
                    from decimal import Decimal

                    await OfflineService.on_paid(
                        order_no=order_no,
                        amount=Decimal(order["paid_amount"]) / 100,  # 转为元
                        coupon_discount=Decimal(order["amount"] - order["paid_amount"]) / 100 if order[
                            "coupon_id"] else Decimal(0)
                    )
                except Exception as e:
                    logger.error(f"[offline-pay] 资金分账失败（需人工处理）: {e}")
                    # 分账失败不影响支付成功，记录错误即可

                conn.commit()
                logger.info(f"[offline-pay] 线下订单支付成功: {order_no}")

        return "<xml><return_code><![CDATA[SUCCESS]]></return_code></xml>"

    except Exception as e:
        logger.error(f"[offline-pay] 处理失败: {e}", exc_info=True)
        return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"


async def _handle_online_pay_notify(order_no: str, wx_total: int, data: dict) -> str:
    """
    处理线上商城订单支付回调（原有逻辑提取为独立函数）
    """
    try:
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 查询订单信息，包含 original_amount
                cur.execute(
                    "SELECT id,user_id,total_amount,status,delivery_way,"
                    "pending_points,pending_coupon_id,original_amount "
                    "FROM orders WHERE order_number=%s FOR UPDATE",
                    (order_no,)
                )
                order = cur.fetchone()
                if not order:
                    raise ValueError("订单号不存在")
                if order["status"] != "pending_pay":
                    return "<xml><return_code><![CDATA[SUCCESS]]></return_code></xml>"

                # 3. 金额核对
                db_total = int(Decimal(order["total_amount"]) * 100)
                db_total -= int(order["pending_points"] or 0) * 100
                coupon_amt = Decimal('0')

                # ====== 关键修复：增加优惠券状态校验 ======
                if order["pending_coupon_id"]:
                    # 使用 FOR UPDATE 锁定优惠券记录，防止并发
                    cur.execute(
                        """SELECT amount, status, valid_to, user_id 
                           FROM coupons 
                           WHERE id = %s 
                           AND status = 'unused' 
                           AND valid_to >= CURDATE()
                           FOR UPDATE""",
                        (order["pending_coupon_id"],)
                    )
                    coupon_row = cur.fetchone()

                    if not coupon_row:
                        # 优惠券无效（已使用、过期或不存在）
                        logger.error(f"[online-pay] 订单 {order_no} 优惠券校验失败: ID={order['pending_coupon_id']}")
                        raise ValueError(f"优惠券无效或已失效: {order['pending_coupon_id']}")

                    # 验证优惠券所属用户
                    if coupon_row['user_id'] != order['user_id']:
                        logger.error(
                            f"[online-pay] 订单 {order_no} 优惠券用户不匹配: 券用户={coupon_row['user_id']}, 订单用户={order['user_id']}")
                        raise ValueError("优惠券不属于当前订单用户")

                    coupon_amt = Decimal(str(coupon_row["amount"]))
                    db_total -= int(coupon_amt * 100)

                    # 现在可以安全地标记为已使用
                    cur.execute(
                        "UPDATE coupons SET status='used',used_at=NOW() WHERE id=%s",
                        (order["pending_coupon_id"],)
                    )
                    logger.info(
                        f"[online-pay] 订单 {order_no} 优惠券核销成功: ID={order['pending_coupon_id']}, 金额={coupon_amt}")

                if wx_total != db_total:
                    raise ValueError(f"金额不一致 微信{wx_total}≠系统{db_total}")

                # 记录优惠券和积分抵扣金额到订单表（关键修复）
                cur.execute("""
                    UPDATE orders 
                    SET coupon_discount = %s,
                        original_amount = COALESCE(%s, total_amount)
                    WHERE id = %s
                """, (
                    coupon_amt,
                    order["original_amount"] or order["total_amount"],
                    order["id"]
                ))

                # 6. 资金结算（写流水）
                from services.finance_service import FinanceService
                fs = FinanceService()
                fs.settle_order(
                    order_no=order_no,
                    user_id=order["user_id"],
                    order_id=order["id"],
                    points_to_use=order["pending_points"] or 0,
                    coupon_discount=coupon_amt,
                    external_conn=conn
                )

                # 7. 判断是否为虚拟商品订单（所有商品都是虚拟商品）
                cur.execute("""
                    SELECT COUNT(*) as total, 
                           SUM(CASE WHEN p.is_virtual = 1 THEN 1 ELSE 0 END) as virtual_count
                    FROM order_items oi
                    JOIN products p ON oi.product_id = p.id
                    WHERE oi.order_id = %s
                """, (order["id"],))
                item_counts = cur.fetchone()
                total_items = item_counts["total"] or 0
                virtual_count = item_counts["virtual_count"] or 0

                if total_items > 0 and virtual_count == total_items:
                    # 所有商品均为虚拟商品 → 直接完成订单
                    next_status = "completed"
                    cur.execute("UPDATE orders SET completed_at = NOW() WHERE id = %s", (order["id"],))
                else:
                    # 包含实体商品 → 走原有物流流程
                    next_status = "pending_recv" if order["delivery_way"] == "pickup" else "pending_ship"

                from api.order.order import OrderManager
                OrderManager.update_status(order_no, next_status, external_conn=conn)

                conn.commit()

        logger.info(f"[online-pay] 线上订单支付成功: {order_no}")
        return "<xml><return_code><![CDATA[SUCCESS]]></return_code></xml>"

    except Exception as e:
        logger.error(f"[online-pay] 处理失败: {e}", exc_info=True)
        return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"


# 兼容调用：异步统一下单包装（服务内其他模块可能调用 ns.wxpay.async_unified_order）
async def async_unified_order(req: dict) -> dict:
    """
    异步包装：在后台线程调用 core.wx_pay_client.wxpay_client.create_jsapi_order
    目的：兼容原来期望 ns.wxpay.async_unified_order 的调用方式
    """
    if settings.wx_mock_mode_bool:  # ✅ 修改为布尔属性
        import uuid, time
        return {"prepay_id": f"MOCK_PREPAY_{int(time.time())}_{uuid.uuid4().hex[:8]}"}

    from core.wx_pay_client import wxpay_client
    out_trade_no = req.get('out_trade_no')

    # ✅ 关键修复：支持多种金额参数格式
    # 格式1: 直接传 total_fee (分)
    # 格式2: 传 amount.total (微信支付V3标准格式)
    total_fee = req.get('total_fee')
    if total_fee is None:
        amount = req.get('amount', {})
        if isinstance(amount, dict):
            total_fee = amount.get('total')

    # 确保是整数（分）
    try:
        total_fee = int(total_fee) if total_fee else 0
    except (ValueError, TypeError):
        raise ValueError(f"无效的金额参数: {total_fee}")

    if total_fee <= 0:
        raise ValueError(f"支付金额必须大于0: {total_fee}")

    # 提取 openid
    payer = req.get('payer', {})
    openid = payer.get('openid', '') if isinstance(payer, dict) else req.get('openid', '')

    import anyio

    def _sync_call():
        try:
            return wxpay_client.create_jsapi_order(
                out_trade_no=str(out_trade_no),
                total_fee=total_fee,  # ✅ 正确传递 total_fee
                openid=str(openid),
                description=req.get('description', '商品支付')
            )
        except Exception as e:
            # 如果底层是 requests.HTTPError，尝试提取 response 内容以便上层返回友好错误
            try:
                import requests
                if isinstance(e, requests.exceptions.HTTPError) and hasattr(e, 'response'):
                    resp = e.response
                    body = ''
                    try:
                        body = resp.text
                    except Exception:
                        body = str(resp)
                    raise RuntimeError(
                        f"WeChat create_jsapi_order failed: status={getattr(resp, 'status_code', '')} body={body}")
            except Exception:
                pass
            raise

    return await anyio.to_thread.run_sync(_sync_call)
