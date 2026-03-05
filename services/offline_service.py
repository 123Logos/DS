# services/offline_service.py
from __future__ import annotations
from decimal import Decimal
from datetime import datetime, timedelta
from typing import Optional, Union, TYPE_CHECKING
import os

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
from services.wechat_api import get_wxacode_unlimit   # ✅ 新增导入
import base64
from services.wechat_api import get_wxacode

logger = get_logger(__name__)

# -------------- 运行时 wxpay 初始化 --------------
if not settings.wx_mock_mode_bool:   # ✅ 修改为布尔属性
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
        invite_code: str = "",
        user_id: Optional[int] = None,
    ) -> dict:
        import uuid
        # 当前登录用户（UUID 字符串）即为商户号
        current_user_id = str(user_id)  # Bearer UUID
        order_no = f"OFF{datetime.now().strftime('%Y%m%d%H%M%S')}{uuid.uuid4().hex[:6]}"
        expire = datetime.now() + timedelta(seconds=settings.qrcode_expire_seconds)
        path = f"pages/offline/pay?orderNo={order_no}&channel=1"
        scene = f"o={order_no}"
        qrcode_b64 = base64.b64encode(await get_wxacode(path=path, scene=scene)).decode()
        qrcode_url = f"data:image/png;base64,{qrcode_b64}"  

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
        return {"order_no": order_no, "qrcode_b64": qrcode_b64, "expire_at": expire}

    # ---------- 2. 刷新收款码（限 1 次） ----------
    @staticmethod
    async def refresh_qrcode(order_no: str, user_id: int) -> dict:
        expire = datetime.now() + timedelta(seconds=settings.qrcode_expire_seconds)
        current_user_id = str(user_id)

        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 1. 查询当前状态（注意 status 后面要有空格或换行）
                cur.execute(
                    "SELECT refresh_count, status "  # ← 注意这里加了一个空格
                    "FROM offline_order "
                    "WHERE order_no=%s AND merchant_id=%s",
                    (order_no, current_user_id)
                )
                row = cur.fetchone()
                
                if not row or row["status"] != 1:
                    raise ValueError("订单不存在或状态异常")
                if row["refresh_count"] >= 1:
                    raise ValueError("收款码已刷新一次，请重新创建订单")

                # 2. 生成新二维码
                path = f"pages/offline/pay?orderNo={order_no}&channel=1"  # ← 修正了括号错误 ${...} → {...}
                scene = f"o={order_no}"
                new_qrcode_b64 = base64.b64encode(await get_wxacode(path=path, scene=scene)).decode()

                # 3. 【关键缺失】更新数据库
                cur.execute(
                    "UPDATE offline_order "
                    "SET qrcode_url=%s, qrcode_expire=%s, refresh_count=refresh_count+1 "
                    "WHERE order_no=%s AND merchant_id=%s",
                    (f"data:image/png;base64,{new_qrcode_b64}", expire, order_no, current_user_id)
                )
                conn.commit()

        return {"qrcode_b64": new_qrcode_b64, "expire_at": expire}

    # ---------- 3. 订单详情 + 可用优惠券 ----------
    @staticmethod
    async def get_order_detail(order_no: str, user_id: int) -> dict:
        current_user_id = str(user_id)
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 先按「商家查自己订单」查；查不到则按「仅订单号」查（顾客打开支付页）
                cur.execute(
                    "SELECT order_no, amount, store_name, product_name, status, merchant_id "
                    "FROM offline_order WHERE order_no=%s AND merchant_id=%s",
                    (order_no, current_user_id)
                )
                order = cur.fetchone()
                if not order:
                    cur.execute(
                        "SELECT order_no, amount, store_name, product_name, status, merchant_id "
                        "FROM offline_order WHERE order_no=%s",
                        (order_no,)
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

    @staticmethod
    async def unified_order(
            order_no: str,
            coupon_id: Optional[int],
            user_id: int,
            openid: str,
            total_fee: Optional[int] = None,
    ) -> dict:
        """total_fee: 单位分，前端传入；当库内金额为 0 或异常时用作兜底传给微信统一下单。"""
        current_user_id = str(user_id)  # 当前登录用户ID（顾客）

        # ========== 新增：检查微信支付配置 ==========
        if settings.wx_mock_mode_bool:   # ✅ 使用布尔属性
            logger.warning("⚠️ 当前处于微信支付 Mock 模式，将返回模拟支付参数")
            logger.warning("⚠️ 如需真实支付，请设置 WX_MOCK_MODE=false 并配置正确的商户信息")

        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 1. 查询订单原始金额（仅用订单号，移除商家ID条件）
                cur.execute(
                    "SELECT amount, status, merchant_id, user_id FROM offline_order WHERE order_no=%s",
                    (order_no,)
                )
                row = cur.fetchone()
                if not row or row["status"] != 1:
                    raise ValueError("订单不存在或不可支付")


                original_amount: int = row["amount"]
                final_amount = original_amount
                coupon_discount = 0

                # 2. 验证并应用优惠券
                if coupon_id:
                    fs = FinanceService()
                    coupons = fs.get_user_coupons(user_id=user_id, status='unused')
                    target_coupon = next((c for c in coupons if c['id'] == coupon_id), None)
                    
                    if not target_coupon:
                        raise ValueError("优惠券无效或已被使用")
                    if target_coupon.get('applicable_product_type') == 'member_only':
                        raise ValueError("该优惠券仅限会员商品使用")
                    
                    coupon_discount = int(target_coupon['amount'] * 100)
                    if coupon_discount > original_amount:
                        raise ValueError("优惠券金额大于订单金额")
                    
                    final_amount = original_amount - coupon_discount

                # 3. 更新订单：保存优惠券ID和实付金额
                cur.execute(
                    """UPDATE offline_order 
                    SET coupon_id=%s, 
                        paid_amount=%s,
                        updated_at=NOW()
                    WHERE order_no=%s""",
                    (coupon_id, final_amount, order_no)
                )

        # 金额兜底：库内为 0 或异常时用前端传的 total_fee（分），避免微信报「缺少参数 total_fee」
        amount_for_wx = final_amount if final_amount and final_amount > 0 else (total_fee or 0)
        if amount_for_wx <= 0:
            raise ValueError("订单金额异常或未传 total_fee，无法发起支付")

        # 4. 调用微信统一下单
        try:
            # ========== 修改：优先使用核心微信支付客户端 ==========
            from core.wx_pay_client import wxpay_client

            if settings.wx_mock_mode_bool:   # ✅ 使用布尔属性
                # Mock 模式：生成模拟支付参数
                logger.info(f"[MOCK] 模拟统一下单: order_no={order_no}, amount={amount_for_wx}")
                prepay_id = f"MOCK_PREPAY_{int(datetime.now().timestamp())}_{user_id}"

                # 生成 Mock 支付参数（使用 RSA 签名格式，但值为 mock）
                import uuid, time
                timestamp = str(int(time.time()))
                nonce_str = uuid.uuid4().hex

                pay_params = {
                    "appId": settings.WECHAT_APP_ID,
                    "timeStamp": timestamp,
                    "nonceStr": nonce_str,
                    "package": f"prepay_id={prepay_id}",
                    "signType": "RSA",
                    "paySign": "MOCK_SIGN_PLACEHOLDER",  # Mock 签名，前端可识别
                }

                logger.info(f"[MOCK] 返回支付参数: {pay_params}")
            else:
                # 真实微信支付模式
                logger.info(f"[WeChatPay] 调用真实统一下单: order_no={order_no}, amount={amount_for_wx}")

                # 使用核心微信支付客户端创建订单
                store_name = row.get('store_name', '') if row else ''
                wx_response = wxpay_client.create_jsapi_order(
                    out_trade_no=order_no,
                    total_fee=amount_for_wx,
                    openid=openid,
                    description=f"线下订单-{store_name}"
                )

                prepay_id = wx_response.get('prepay_id')
                if not prepay_id:
                    logger.error(f"微信统一下单失败: {wx_response}")
                    raise ValueError(f"微信统一下单失败: {wx_response.get('message', '未知错误')}")

                logger.info(f"[WeChatPay] 获取 prepay_id 成功: {prepay_id}")

                # 使用核心客户端生成前端支付参数（包含真实签名）
                pay_params = wxpay_client.generate_jsapi_pay_params(prepay_id)
                logger.info(f"[WeChatPay] 生成支付参数成功")

            return {
                "pay_params": pay_params,
                "original_amount": original_amount,
                "coupon_discount": coupon_discount,
                "final_amount": final_amount
            }

        except Exception as e:
            logger.error(f"微信支付调用失败: {e}", exc_info=True)
            raise ValueError(f"支付调用失败: {str(e)}")

    
    # ---------- 5. 订单列表 ----------
    @staticmethod
    async def list_orders(
        merchant_id: Optional[int] = None, 
        user_id: Optional[int] = None, 
        page: int = 1, 
        size: int = 20
    ):
        """
        查询订单列表，支持按商家ID（卖方）或用户ID（买方）查询
        
        Args:
            merchant_id: 商家ID（卖方），与 user_id 互斥
            user_id: 用户ID（买方），与 merchant_id 互斥
            page: 页码，从1开始
            size: 每页数量
        """
        # 参数校验
        if not merchant_id and not user_id:
            raise ValueError("请传入 merchant_id 或 user_id 其中一个参数")
        if merchant_id and user_id:
            raise ValueError("merchant_id 和 user_id 不能同时传入")
        
        offset = (page - 1) * size
        
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 动态构建查询条件
                if merchant_id:
                    # 按商家查询（卖方视角）
                    current_user_id = str(merchant_id)
                    where_clause = "WHERE merchant_id=%s"
                    params = (current_user_id, size, offset)
                else:
                    # 按用户查询（买方视角）
                    current_user_id = str(user_id)
                    where_clause = "WHERE user_id=%s"
                    params = (current_user_id, size, offset)
                
                # 查询总数
                count_sql = f"SELECT COUNT(*) as total FROM offline_order {where_clause}"
                cur.execute(count_sql, (params[0],))
                total = cur.fetchone()["total"]
                
                # 查询分页数据
                data_sql = (
                    "SELECT order_no,store_name,amount,paid_amount,status,"
                    "coupon_id,coupon_discount,created_at,pay_time "
                    f"FROM offline_order {where_clause} "
                    "ORDER BY id DESC LIMIT %s OFFSET %s"
                )
                cur.execute(data_sql, params)
                rows = cur.fetchall()
                
                # 格式化金额（分转元）
                for row in rows:
                    row["amount_yuan"] = row["amount"] / 100 if row["amount"] else 0
                    row["paid_amount_yuan"] = row["paid_amount"] / 100 if row.get("paid_amount") else 0
                    row["coupon_discount_yuan"] = row["coupon_discount"] / 100 if row.get("coupon_discount") else 0
        
        return {
            "list": rows, 
            "page": page, 
            "size": size,
            "total": total,
            "total_pages": (total + size - 1) // size
        }

    # ---------- 6. 退款 ----------
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

    # ---------- 7. 收款码状态 ----------
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


    # ---------- 8. 供优惠券接口调用的原始订单 ----------
    @staticmethod
    async def get_raw_order(order_no: str, merchant_id: str):
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute(
                    "SELECT order_no,amount,status FROM offline_order WHERE order_no=%s AND merchant_id=%s",
                    (order_no, merchant_id)
                )
                return cur.fetchone()
            
    @staticmethod
    async def on_paid(order_no: str, amount: Decimal, coupon_discount: Decimal = Decimal(0)):
        """
        线下订单支付成功后的资金分账（独立简化版）
        【与线上订单完全隔离，仅处理资金池分配】
        """
        from services.finance_service import FinanceService
        
        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 查询订单信息
                cur.execute(
                    "SELECT merchant_id, store_name, user_id FROM offline_order WHERE order_no=%s",
                    (order_no,)
                )
                order = cur.fetchone()
                if not order:
                    logger.error(f"[on_paid] 订单不存在: {order_no}")
                    return

                # 1️⃣ 插入平台订单表（仅用于财务对账，status=completed 表示直接完成）
                # （如果不需要对账可删除此段）
                cur.execute(
                    """INSERT INTO orders (order_number, user_id, merchant_id, total_amount, status,
                    offline_order_flag, pay_way, created_at, coupon_discount) 
                    VALUES (%s, %s, %s, %s, 'completed', 1, 'wechat', NOW(), %s)""",
                    (order_no, order["user_id"], order["merchant_id"], amount, coupon_discount)
                )
                
                # 2️⃣ 资金分账（简化版：只分池子，不发奖励）
                finance = FinanceService()
                allocs = finance.get_pool_allocations()
                merchant_ratio = allocs.get('merchant_balance', Decimal('0.80'))
                merchant_amount = amount * merchant_ratio
                
                # 平台收入池记账（100%）
                finance._add_pool_balance(
                    cur, 'platform_revenue_pool', amount,
                    f"线下订单收入: {order_no}", order["merchant_id"]
                )
                
                # 各子池分配（20%）
                for pool_type, ratio in allocs.items():
                    if pool_type == 'merchant_balance' or ratio <= 0:
                        continue
                    alloc_amount = amount * ratio
                    # 从平台池扣减
                    finance._add_pool_balance(
                        cur, 'platform_revenue_pool', -alloc_amount,
                        f"线下订单分配: {order_no} -> {pool_type}", order["merchant_id"]
                    )
                    # 子池增加
                    finance._add_pool_balance(
                        cur, pool_type, alloc_amount,
                        f"线下订单收入: {order_no}", order["merchant_id"]
                    )
                
                conn.commit()
            
            # 3️⃣ 商户实时到账（调用已有逻辑）
            # 注意：这里转的是扣除平台抽成后的金额
            await notify_merchant(
                merchant_id=order["merchant_id"],
                order_no=order_no,
                amount=int(merchant_amount * 100)  # 转为分
            )
            
            logger.info(f"[on_paid] 线下订单完成: {order_no}, 金额: {amount}, 商户实收: {merchant_amount}")

# ==================== 新增：生成永久收款码 ====================
    @staticmethod
    async def generate_permanent_qrcode(merchant_id: int) -> dict:
        """
        为指定商家生成永久有效的小程序码
        返回 base64 图片数据及过期时间（长期有效，expire_at 返回 None）
        """
        # 场景值编码（长度限制32字符）
        scene = f"m={merchant_id}"
        # 固定页面路径（需要在小程序中创建该页面）
        page = "pages/offline/permanentPay"

        try:
            # 调用微信接口获取二维码图片二进制
            qrcode_bytes = await get_wxacode_unlimit(scene, page)
            qrcode_base64 = base64.b64encode(qrcode_bytes).decode()
            qrcode_data_url = f"data:image/png;base64,{qrcode_base64}"

            # 保存到数据库（幂等操作）
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 检查是否已存在
                    cur.execute(
                        "SELECT id FROM merchant_qrcode WHERE merchant_id = %s",
                        (merchant_id,)
                    )
                    if cur.fetchone():
                        # 更新
                        cur.execute(
                            "UPDATE merchant_qrcode SET qrcode_data = %s, updated_at = NOW() WHERE merchant_id = %s",
                            (qrcode_data_url, merchant_id)
                        )
                    else:
                        # 插入
                        cur.execute(
                            "INSERT INTO merchant_qrcode (merchant_id, qrcode_data) VALUES (%s, %s)",
                            (merchant_id, qrcode_data_url)
                        )
                    conn.commit()

            return {
                "qrcode": qrcode_data_url,
                "expire_at": None,  # 永久有效
                "merchant_id": merchant_id
            }
        except Exception as e:
            logger.error(f"生成商户{merchant_id}永久二维码失败: {e}", exc_info=True)
            raise
    # ==============================================================

# ==================== 新增：用户创建订单（永久码场景） ====================
    @staticmethod
    async def create_order_for_user(merchant_id: int, user_id: int, amount: int, coupon_id: Optional[int] = None) -> str:
        """
        创建订单（不生成二维码），用于永久码场景。
        :param merchant_id: 商家ID
        :param user_id: 用户ID
        :param amount: 订单金额（分）
        :param coupon_id: 优惠券ID（可选）
        :return: 订单号
        """
        import uuid
        # ----- 新增：查询商家店铺名称 -----
        store_name = "默认店铺"  # 兜底值
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT store_name FROM merchant_stores WHERE user_id = %s", (merchant_id,))
                row = cur.fetchone()
                if row:
                    store_name = row['store_name']
        # ------------------------------
        order_no = f"OFF{datetime.now().strftime('%Y%m%d%H%M%S')}{uuid.uuid4().hex[:6]}"
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 插入订单，状态为待支付（1）
                cur.execute("""
                    INSERT INTO offline_order
                    (order_no, merchant_id, user_id, amount, coupon_id, store_name, status)
                    VALUES (%s, %s, %s, %s, %s, %s, 1)
                """, (order_no, merchant_id, user_id, amount, coupon_id, store_name))
                conn.commit()
        return order_no
    # ==============================================================