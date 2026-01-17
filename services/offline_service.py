# services/offline_service.py
from __future__ import annotations
from decimal import Decimal
from datetime import datetime, timedelta
from typing import Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from wechatpayv3 import WeChatPay      # 仅为静态检查服务

from core.database import get_conn
from core.config import settings
from core.logging import get_logger
from services.finance_service import FinanceService
from services.notify_service import notify_merchant
from pathlib import Path
import pymysql
import xmltodict

logger = get_logger(__name__)

# -------------- 运行时 wxpay 初始化 --------------
if not settings.WX_MOCK_MODE:
    from wechatpayv3 import WeChatPay, WeChatPayType
    priv_path = Path(settings.WECHAT_PAY_API_KEY_PATH)
    if not priv_path.exists():
        raise RuntimeError(f"WeChat private key file not found: {priv_path}")
    private_key = priv_path.read_text(encoding="utf-8")

    public_key = None
    if settings.WECHAT_PAY_PUBLIC_KEY_PATH:
        pub_path = Path(settings.WECHAT_PAY_PUBLIC_KEY_PATH)
        if pub_path.exists():
            public_key = pub_path.read_text(encoding="utf-8")
        else:
            logger.warning(f"WeChat public key file not found: {pub_path}")

    wxpay: WeChatPay = WeChatPay(
        wechatpay_type=WeChatPayType.MINIPROG,
        mchid=settings.WECHAT_PAY_MCH_ID,
        private_key=private_key,
        cert_serial_no=settings.WECHAT_CERT_SERIAL_NO,
        apiv3_key=settings.WECHAT_PAY_API_V3_KEY,
        appid=settings.WECHAT_APP_ID,
        public_key=public_key,
        public_key_id=settings.WECHAT_PAY_PUB_KEY_ID,
    )
else:
    wxpay: WeChatPay | None = None


class OfflineService:
    # ---------- 1. 创建线下支付单 ----------
    @staticmethod
    async def create_order(
        merchant_id: int,
        store_name: str,
        amount: int,
        product_name: str = "",
        remark: str = "",
        user_id: Optional[int] = None,
    ) -> dict:
        import uuid
        # 当前登录用户（UUID 字符串）即为商户号
        current_user_id = str(user_id)  # Bearer UUID
        order_no = f"OFF{datetime.now().strftime('%Y%m%d%H%M%S')}{uuid.uuid4().hex[:6]}"
        expire = datetime.now() + timedelta(seconds=settings.qrcode_expire_seconds)
        qrcode_url = f"https://your-domain.com/offline/pay?order_no={order_no}"

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO offline_order "
                    "(order_no,merchant_id,user_id,store_name,amount,product_name,remark,"
                    "qrcode_url,qrcode_expire,status) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,1)",
                    (order_no, current_user_id, user_id, store_name, amount,
                     product_name, remark, qrcode_url, expire)
                )
                conn.commit()

        logger.info(f"[Offline] 创建订单 {order_no} 金额 {amount} 商户={current_user_id}")
        return {"order_no": order_no, "qrcode_url": qrcode_url, "expire_at": expire}

    # ---------- 2. 刷新收款码（限 1 次） ----------
    @staticmethod
    async def refresh_qrcode(order_no: str, user_id: int) -> dict:
        expire = datetime.now() + timedelta(seconds=settings.qrcode_expire_seconds)
        new_url = f"https://your-domain.com/offline/pay?order_no={order_no}"
        current_user_id = str(user_id)  # Bearer UUID

        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT refresh_count,status FROM offline_order "
                    "WHERE order_no=%s AND merchant_id=%s",
                    (order_no, current_user_id)
                )
                row = cur.fetchone()
                if not row or row["status"] != 1:
                    raise ValueError("订单不存在或状态异常")
                if row["refresh_count"] >= 1:
                    raise ValueError("收款码已刷新一次，请重新创建订单")

                cur.execute(
                    "UPDATE offline_order SET qrcode_url=%s,qrcode_expire=%s,refresh_count=refresh_count+1 "
                    "WHERE order_no=%s AND merchant_id=%s",
                    (new_url, expire, order_no, current_user_id)
                )
                conn.commit()

        logger.info(f"[Offline] 刷新码 {order_no} 商户={current_user_id}")
        return {"qrcode_url": new_url, "expire_at": expire}

    # ---------- 3. 订单详情 + 可用优惠券 ----------
    @staticmethod
    async def get_order_detail(order_no: str, user_id: int) -> dict:
        current_user_id = str(user_id)
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT order_no,amount,store_name,product_name,status "
                    "FROM offline_order WHERE order_no=%s AND merchant_id=%s",
                    (order_no, current_user_id)
                )
                order = cur.fetchone()
                if not order:
                    raise ValueError("订单不存在")

                svc = FinanceService()
                coupons = svc.list_available(user_id, order["amount"])
                for c in coupons:
                    c["amount"] = float(c["amount"])
                    c["threshold"] = float(c["threshold"])

        return {**order, "coupons": coupons}

    # ---------- 4. 统一下单（核销优惠券 + 调起支付） ----------
    @staticmethod
    async def unified_order(
        order_no: str,
        coupon_id: Optional[int],
        user_id: int,
    ) -> dict:
        current_user_id = str(user_id)
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT amount,status,merchant_id FROM offline_order WHERE order_no=%s AND merchant_id=%s",
                    (order_no, current_user_id)
                )
                row = cur.fetchone()
                if not row or row["status"] != 1:
                    raise ValueError("订单不可支付")
                amount: int = row["amount"]

                if coupon_id:
                    amount = await FinanceService.apply_coupon(
                        user_id=user_id, coupon_id=coupon_id, amount=amount
                    )

                cur.execute(
                    "UPDATE offline_order SET amount=%s WHERE order_no=%s AND merchant_id=%s",
                    (amount, order_no, current_user_id)
                )
                conn.commit()

        import uuid, time
        return {
            "appId": "wx123456",
            "timeStamp": str(int(time.time())),
            "nonceStr": uuid.uuid4().hex,
            "package": f"prepay_id=wx{int(time.time())}",
            "signType": "RSA",
            "paySign": "fake_sign"
        }

    # ---------------- 5. 支付回调（接收原始 dict） ----------------
    @staticmethod
    async def handle_notify(raw_xml: bytes) -> str:
        """
        微信异步通知入口
        返回 SUCCESS 表示已收到，微信不再重试；其余都视为失败
        """
        try:
            # 1. 解析 XML
            data = xmltodict.parse(raw_xml.decode("utf-8"))["xml"]

            # 2. 验签（Mock 模式跳过）
            if not settings.WX_MOCK_MODE:
                if not wxpay.verify_signature(data):
                    logger.warning("[notify] 验签失败")
                    return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"

            # 3. 基本字段校验
            if data.get("return_code") != "SUCCESS" or data.get("result_code") != "SUCCESS":
                logger.warning(f"[notify] 微信通知失败包: {data}")
                return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"

            order_no = data["out_trade_no"]
            transaction_id = data["transaction_id"]
            pay_time = data["time_end"]          # 20220101123456

            # 4. 查库
            with get_conn() as conn:
                with conn.cursor(pymysql.cursors.DictCursor) as cur:
                    cur.execute(
                        "SELECT id,amount,status,merchant_id FROM offline_order WHERE order_no=%s",
                        (order_no,)
                    )
                    order = cur.fetchone()
                    if not order or order["status"] != 1:
                        logger.warning(f"[notify] 订单不存在或已处理: {order_no}")
                        return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"

                    # 5. 幂等更新
                    cur.execute(
                        "UPDATE offline_order SET status=2,pay_time=STR_TO_DATE(%s,'%Y%m%d%H%i%s'),"
                        "transaction_id=%s WHERE order_no=%s AND status=1",
                        (pay_time, transaction_id, order_no)
                    )
                    if cur.rowcount == 0:
                        return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"
                    conn.commit()

            # 6. 业务后处理
            await OfflineService.on_paid(order_no, Decimal(order["amount"]) / 100)
            logger.info(f"[notify] 支付成功：{order_no}")
            return "<xml><return_code><![CDATA[SUCCESS]]></return_code></xml>"

        except Exception as e:
            logger.exception(f"[notify] 处理异常: {e}")
            return "<xml><return_code><![CDATA[FAIL]]></return_code></xml>"
    # ---------- 6. 订单列表 ----------
    @staticmethod
    async def list_orders(merchant_id: int, page: int, size: int):
        current_user_id = str(merchant_id)  # merchant_id 即当前登录用户 UUID
        offset = (page - 1) * size
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT order_no,store_name,amount,status,created_at "
                    "FROM offline_order WHERE merchant_id=%s "
                    "ORDER BY id DESC LIMIT %s OFFSET %s",
                    (current_user_id, size, offset)
                )
                rows = cur.fetchall()
        return {"list": rows, "page": page, "size": size}

    # ---------- 7. 退款 ----------
    @staticmethod
    async def refund(order_no: str, refund_amount: Optional[int], user_id: int):
        current_user_id = str(user_id)
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT id,amount,status FROM offline_order WHERE order_no=%s AND merchant_id=%s",
                    (order_no, current_user_id)
                )
                row = cur.fetchone()
                if not row or row["status"] != 2:
                    raise ValueError("订单未支付")
                amount = row["amount"]
                money = refund_amount or amount

                cur.execute(
                    "UPDATE offline_order SET status=4 WHERE order_no=%s AND merchant_id=%s",
                    (order_no, current_user_id)
                )
                conn.commit()

        await FinanceService.refund_order(order_no)
        logger.info(f"[Offline] 退款 {order_no} 金额 {money} 商户={current_user_id}")
        return {"refund_no": f"REF{order_no}"}

    # ---------- 8. 收款码状态 ----------
    @staticmethod
    async def qrcode_status(order_no: str, merchant_id: int):
        # 直接拿传入的 merchant_id（当前登录用户）
        current_user_id = str(merchant_id)
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT status,qrcode_expire FROM offline_order "
                    "WHERE order_no=%s AND merchant_id=%s",
                    (order_no, current_user_id)
                )
                row = cur.fetchone()
                if not row:
                    raise ValueError("订单不存在")
                now = datetime.now()
                if row["status"] != 1:
                    return {"status": "paid" if row["status"] == 2 else "closed"}
                if row["qrcode_expire"] < now:
                    return {"status": "expired"}
                return {"status": "valid"}


    # ---------- 9. 供优惠券接口调用的原始订单 ----------
    @staticmethod
    async def get_raw_order(order_no: str, merchant_id: str):
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT order_no,amount,status FROM offline_order WHERE order_no=%s AND merchant_id=%s",
                    (order_no, merchant_id)
                )
                return cur.fetchone()
            
    # ---------------- 10. 支付成功后续 ----------------
    @staticmethod
    async def on_paid(order_no: str, amount: Decimal):
        """
        1. 写平台订单表（分账用）
        2. 给商家微信零钱转账 + 模板消息
        """
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 1. 插入平台订单（注意 merchant_id 在 offline_order 是字符串 UUID，这里直接复用）
                cur.execute(
                    "INSERT INTO orders (order_number,user_id,merchant_id,total_amount,status,"
                    "offline_order_flag,pay_way,created_at) "
                    "SELECT order_no,user_id,merchant_id,amount,'completed',1,'wechat',NOW() "
                    "FROM offline_order WHERE order_no=%s",
                    (order_no,)
                )
                order_id = cur.lastrowid

                # 2. 调用财务模块分账（积分、资金池、奖励等）
                finance = FinanceService()
                finance.settle_order(
                    order_no=order_no,
                    user_id=0,               # 线下订单无 buyer 账号，传 0
                    order_id=order_id,
                    points_to_use=Decimal(0),
                    coupon_discount=Decimal(0)
                )
                conn.commit()

        # 3. 给商家微信零钱转账 + 模板消息
        #    注意：notify_merchant 需要 int merchant_id，而表里存的是 UUID 字符串，
        #    这里简单用 1 代替，真实环境请用 users.id 关联
        await notify_merchant(merchant_id=1, order_no=order_no, amount=int(amount * 100))