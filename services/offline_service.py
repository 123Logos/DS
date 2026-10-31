# services/offline_service.py
from __future__ import annotations
from decimal import Decimal
from datetime import datetime, timedelta
from typing import Optional, Union, TYPE_CHECKING, Any
import os
import json

if TYPE_CHECKING:
    from wechatpayv3 import WeChatPay  # 仅为静态检查服务

from core.database import get_conn
from core.config import settings
from core.logging import get_logger
from services.finance_service import FinanceService, NOMINAL_SUBPOOL_SLICE
from services.notify_service import notify_merchant
from pathlib import Path
import pymysql
import xmltodict
from services.wechat_api import get_wxacode_unlimit  # ✅ 新增导入
import base64
from services.wechat_api import get_wxacode
from cryptography import x509
from cryptography.hazmat.backends import default_backend
# used for plain QR code generation (added to pyproject)

logger = get_logger(__name__)

def _load_cert_serial_no(cert_path: str) -> str:
    try:
        path = Path(cert_path)
        if not path.exists():
            raise FileNotFoundError(f"微信支付证书文件不存在: {path}")
        with path.open("rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
        serial = format(cert.serial_number, "x").upper()
        logger.info(f"[WeChat] loaded merchant cert serial_no from {path}: {serial}")
        return serial
    except Exception as exc:
        logger.warning('payment_cert_load_failed')
        return ""


# -------------- 运行时 wxpay 初始化 --------------
if not settings.wx_mock_mode_bool:  # ✅ 修改为布尔属性
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

    cert_serial_no = settings.WECHAT_CERT_SERIAL_NO
    if not cert_serial_no and settings.WECHAT_PAY_API_CERT_PATH:
        cert_serial_no = _load_cert_serial_no(settings.WECHAT_PAY_API_CERT_PATH)

    if not cert_serial_no:
        raise RuntimeError("微信支付证书序列号未配置或读取失败，请检查 WECHAT_CERT_SERIAL_NO 和 WECHAT_PAY_API_CERT_PATH")

    wxpay: WeChatPay = WeChatPay(
        wechatpay_type=WeChatPayType.MINIPROG,
        mchid=settings.WECHAT_PAY_MCH_ID,
        private_key=private_key,
        cert_serial_no=cert_serial_no,
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

        return {**order, "coupons": coupons}

    # services/offline_service.py 中的 unified_order 方法

    @staticmethod
    def _merge_offline_coupon_ids(
        coupon_ids: Optional[list[int]] = None,
        coupon_id: Optional[int] = None,
    ) -> list[int]:
        ids: list[int] = []
        if coupon_ids:
            ids.extend(int(x) for x in coupon_ids if x is not None)
        if coupon_id is not None and int(coupon_id) != 0:
            ids.append(int(coupon_id))
        # 去重 + 稳定排序（便于日志/对账）
        return sorted({i for i in ids if i > 0})

    @staticmethod
    async def unified_order(
            order_no: str,
            coupon_id: Optional[int],
            user_id: int,
            openid: str,
            total_fee: Optional[int] = None,
            coupon_ids: Optional[list[int]] = None,
    ) -> dict:
        from services.finance_service import FinanceService, max_coupon_total_yuan  # 添加此行
        """total_fee: 单位分，前端传入；当库内金额为 0 或异常时用作兜底传给微信统一下单。"""
        current_user_id = str(user_id)  # 当前登录用户ID（顾客）

        # ========== 新增：检查微信支付配置 ==========
        if settings.wx_mock_mode_bool:  # ✅ 使用布尔属性
            logger.warning("⚠️ 当前处于微信支付 Mock 模式，将返回模拟支付参数")
            logger.warning("⚠️ 如需真实支付，请设置 WX_MOCK_MODE=false 并配置正确的商户信息")

        with get_conn() as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 1. 查询订单原始金额（仅用订单号，移除商家ID条件）
                cur.execute(
                    "SELECT amount,paid_amount,coupon_ids,coupon_id,status,merchant_id,user_id,store_name,security_prepay_frozen FROM offline_order WHERE order_no=%s FOR UPDATE",
                    (order_no,)
                )
                row = cur.fetchone()
                if not row or row["status"] != 1:
                    raise ValueError("订单不存在或不可支付")
                if row.get('user_id') is not None and int(row['user_id']) != int(user_id):
                    raise ValueError('无权支付该订单')
                cur.execute('SELECT openid FROM users WHERE id=%s', (user_id,))
                payer = cur.fetchone()
                if not payer or payer.get('openid') != openid:
                    raise ValueError('支付身份不匹配')
                cur.execute('UPDATE offline_order SET user_id=%s WHERE order_no=%s', (user_id, order_no))

                original_amount: int = row["amount"]
                final_amount = original_amount
                coupon_discount = 0
                target_coupon_ids = OfflineService._merge_offline_coupon_ids(
                    coupon_ids=coupon_ids,
                    coupon_id=coupon_id,
                )
                if row.get('security_prepay_frozen'):
                    from services.finance_service import parse_offline_coupon_ids
                    if target_coupon_ids != parse_offline_coupon_ids(row):
                        raise ValueError('订单优惠已锁定')

                # 2. 验证并应用优惠券（支持多张叠加）
                if target_coupon_ids:
                    fs = FinanceService()
                    coupons = fs.get_user_coupons(user_id=user_id, status='unused')
                    coupon_by_id = {int(c["id"]): c for c in coupons}

                    total_discount = 0
                    for cid in target_coupon_ids:
                        c = coupon_by_id.get(int(cid))
                        if not c:
                            raise ValueError(f"优惠券无效或已被使用: {cid}")
                        if c.get("applicable_product_type") == "member_only":
                            raise ValueError("该优惠券仅限会员商品使用")
                        total_discount += int(Decimal(str(c["amount"])) * 100)

                    # 与线上一致：券叠加上限 = ceil(商品金额) 到元；实际抵扣封顶到订单金额（见 cap_discounts_to_merchandise_total）
                    merchandise_yuan = (Decimal(original_amount) / Decimal(100)).quantize(Decimal("0.01"))
                    max_coupon_yuan = max_coupon_total_yuan(merchandise_yuan, Decimal("0"))
                    max_coupon_fen = int(max_coupon_yuan * Decimal(100))
                    if total_discount > max_coupon_fen:
                        raise ValueError("优惠券合计抵扣超过允许上限")

                    coupon_discount = min(total_discount, original_amount)
                    final_amount = original_amount - coupon_discount

                # 更新实付金额
                coupon_ids_json = json.dumps(target_coupon_ids) if target_coupon_ids else None
                primary_coupon_id = target_coupon_ids[0] if target_coupon_ids else None
                cur.execute(
                    """UPDATE offline_order 
                    SET coupon_id=%s,
                        coupon_ids=%s,
                        coupon_discount=%s,
                        paid_amount=%s,
                        security_prepay_frozen=1, updated_at=NOW()
                    WHERE order_no=%s""",
                    (primary_coupon_id, coupon_ids_json, coupon_discount, final_amount, order_no)
                )
                if final_amount <= 0:
                    for cid in target_coupon_ids:
                        cur.execute("UPDATE coupons SET status='used',used_at=NOW() WHERE id=%s AND user_id=%s AND status='unused' AND valid_to>=CURDATE()", (cid, user_id))
                        if cur.rowcount != 1:
                            raise ValueError('优惠券不可用')
                    cur.execute('UPDATE offline_order SET status=2,pay_time=NOW() WHERE order_no=%s', (order_no,))
                    await OfflineService.on_paid(order_no, Decimal(0), Decimal(coupon_discount)/100, external_conn=conn)
                    cur.execute('INSERT INTO payment_events(event_key,order_number,transaction_id,total_fee) VALUES(%s,%s,%s,0)', ('pay:' + order_no, order_no, 'zero:' + order_no))
                conn.commit()

        # ==================== 零元订单处理 ====================
        if final_amount <= 0:
            transfer_warn = None
            # 生成模拟支付参数（与线上订单保持一致）
            import uuid, time
            pay_params = {
                "appId": settings.WECHAT_APP_ID,
                "timeStamp": str(int(time.time())),
                "nonceStr": uuid.uuid4().hex,
                "package": "prepay_id=ZERO_ORDER",
                "signType": "RSA",
                "paySign": "ZERO_ORDER_SIGN"
            }
            out_zero: dict[str, Any] = {
                "pay_params": pay_params,
                "original_amount": original_amount,
                "coupon_discount": coupon_discount,
                "final_amount": final_amount
            }
            if transfer_warn:
                out_zero["merchant_transfer_warning"] = transfer_warn
            return out_zero
        # ===================================================

        amount_for_wx = final_amount
        if amount_for_wx <= 0:
            raise ValueError("订单金额异常或未传 total_fee，无法发起支付")

        # 4. 调用微信统一下单（原有代码保持不变）
        try:
            # ========== 修改：优先使用核心微信支付客户端 ==========
            from core.wx_pay_client import wxpay_client

            if settings.wx_mock_mode_bool:  # ✅ 使用布尔属性
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

                logger.info('mock_offline_prepay_created')
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
                    logger.error('offline_prepay_missing')
                    raise ValueError('微信统一下单失败')

                logger.info('offline_prepay_created')

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
            logger.error('offline_provider_failed')
            raise ValueError('支付服务暂时不可用') from None

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
        from services.refund_service import RefundService
        from core.auth import is_platform_admin
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT merchant_id FROM offline_order WHERE order_no=%s', (order_no,))
                row = cur.fetchone()
                if not row or int(row['merchant_id']) != int(user_id):
                    raise ValueError('无权退款该订单')
        return RefundService.request(order_no, {'id': user_id}, refund_fee=refund_amount, audit=False, merchant_address=None, merchant_actor=True)

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
    async def on_paid(
        order_no: str,
        amount: Decimal,
        coupon_discount: Decimal = Decimal(0),
        transaction_id: Optional[str] = None,
        external_conn=None,
    ) -> Optional[str]:
        """
        线下订单支付成功后的处理：
        - 资金分账（所有子池基于实付+优惠券分配）
        - 发放用户积分
        - 增加公司积分池
        - 通知商家转账

        若微信「商家转账」失败（如 SIGN_ERROR），仅记录日志并返回告警文案，不抛异常，
        避免零元单已核销优惠券后接口仍返回 400。
        """
        from contextlib import nullcontext
        with (nullcontext(external_conn) if external_conn is not None else get_conn()) as conn:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                # 查询订单信息
                cur.execute(
                    "SELECT merchant_id, user_id FROM offline_order WHERE order_no=%s",
                    (order_no,)
                )
                order = cur.fetchone()
                if not order:
                    logger.error(f"[on_paid] 订单不存在: {order_no}")
                    return None

                merchant_id = order["merchant_id"]
                user_id = order["user_id"]
                wx_tid = (transaction_id or "").strip() or None

                # 1. 插入平台订单表（用于对账）；须写入微信 transaction_id，否则统一退款审核读 orders 会缺号
                cur.execute(
                    """INSERT INTO orders (order_number, user_id, merchant_id, total_amount, status,
                       offline_order_flag, pay_way, created_at, coupon_discount, transaction_id) 
                       VALUES (%s, %s, %s, %s, 'completed', 1, 'wechat', NOW(), %s, %s)""",
                    (order_no, user_id, merchant_id, amount, coupon_discount, wx_tid)
                )
                platform_order_id = cur.lastrowid

                # 2. 资金分账
                finance = FinanceService()
                allocs = finance.get_pool_allocations()
                platform_rate = finance.get_distribution_platform_rate()
                subpool_scale = (
                    platform_rate / NOMINAL_SUBPOOL_SLICE
                    if NOMINAL_SUBPOOL_SLICE > 0
                    else Decimal("1")
                )
                # 与线上一致：子池合计占基数 platform_rate，商家占 1−platform_rate（避免收入池轧差为负）
                merchant_ratio = Decimal("1") - platform_rate

                # ✅ 统一基数 = 实付金额 + 优惠券金额
                distribution_base = amount + coupon_discount

                # 与线上 settle_order 一致：线下扫码无商品行，整笔基数视为「普通商品」分摊基数
                normal_paid = distribution_base

                has_referrer = False
                referrer_id = None
                if user_id is not None:
                    cur.execute(
                        "SELECT referrer_id FROM user_referrals WHERE user_id = %s",
                        (user_id,),
                    )
                    ref_row = cur.fetchone()
                    if ref_row and ref_row.get("referrer_id"):
                        cur.execute(
                            "SELECT status FROM users WHERE id = %s",
                            (ref_row["referrer_id"],),
                        )
                        status_row = cur.fetchone()
                        if status_row and status_row.get("status") == 0:
                            has_referrer = True
                            referrer_id = ref_row["referrer_id"]

                merchant_amount = distribution_base * merchant_ratio  # 商家应得总额（含优惠券）

                # 平台收入池记录完整收入
                finance._add_pool_balance(
                    cur, 'platform_revenue_pool', distribution_base,
                    f"线下订单收入: {order_no}", merchant_id
                )

                # 从平台收入池分配各子池（公益基金、维护池、补贴池等）
                for pool_type, ratio in allocs.items():
                    if pool_type == 'merchant_balance' or ratio <= 0:
                        continue
                    alloc_amount = (distribution_base * ratio * subpool_scale).quantize(
                        Decimal("0.000001")
                    )
                    finance._add_pool_balance(
                        cur, 'platform_revenue_pool', -alloc_amount,
                        f"线下订单分配: {order_no} -> {pool_type}", merchant_id
                    )
                    if pool_type == 'fund_pool' and has_referrer and normal_paid > 0:
                        referral_amount = (normal_paid * ratio * subpool_scale).quantize(
                            Decimal("0.000001")
                        )
                        finance._grant_referral_points(cur, referrer_id, referral_amount, order_no)
                        fund_pool_amount = alloc_amount - referral_amount
                        if fund_pool_amount > 0:
                            finance._add_pool_balance(
                                cur,
                                pool_type,
                                fund_pool_amount,
                                f"线下订单#{order_no} fund_pool+{int(ratio * 100)}% (剩余部分)",
                                user_id,
                            )
                    else:
                        finance._add_pool_balance(
                            cur, pool_type, alloc_amount,
                            f"线下订单收入: {order_no}", merchant_id
                        )

                # 3. 用户积分发放（实付部分）
                if amount > 0 and user_id is not None:
                    cur.execute(
                        "UPDATE users SET member_points = COALESCE(member_points, 0) + %s WHERE id = %s",
                        (amount, user_id)
                    )
                    cur.execute("SELECT member_points FROM users WHERE id = %s", (user_id,))
                    new_balance = cur.fetchone()["member_points"]
                    cur.execute(
                        """INSERT INTO points_log (user_id, change_amount, balance_after, type, reason, related_order, created_at)
                           VALUES (%s, %s, %s, 'member', %s, %s, NOW())""",
                        (
                            user_id,
                            amount,
                            new_balance,
                            f"线下订单支付获得积分: {order_no}",
                            platform_order_id,
                        ),
                    )

                # 4. 公司积分池增加（与平台计提比例一致）
                platform_points_amount = distribution_base * platform_rate
                if platform_points_amount > 0:
                    finance._add_pool_balance(
                        cur, 'company_points', platform_points_amount,
                        f"线下订单平台积分: {order_no}", None
                    )

                # ===== 新增：从平台收入池扣除商家应得金额 =====
                finance._add_pool_balance(
                    cur, 'platform_revenue_pool', -merchant_amount,
                    f"线下订单商家结算: {order_no}", merchant_id
                )
                if merchant_amount > 0:
                    import hashlib
                    batch = 'MT' + hashlib.sha256(order_no.encode()).hexdigest()[:30]
                    cur.execute('SELECT openid FROM users WHERE id=%s', (merchant_id,))
                    merchant = cur.fetchone()
                    cur.execute('INSERT INTO payment_merchant_transfers(order_number,merchant_id,beneficiary_openid,amount,out_batch_no) VALUES(%s,%s,%s,%s,%s)', (order_no, merchant_id, merchant.get('openid') if merchant else None, int(merchant_amount * 100), batch))

                if external_conn is None:
                    conn.commit()

        return None

    @staticmethod
    def is_valid_offline_permanent_pay_target(merchant_user_id: int) -> bool:
        """永久收款外链中的 id 须为已开通商户身份的用户（is_merchant>=1）。"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM users WHERE id = %s AND COALESCE(is_merchant, 0) >= 1 LIMIT 1",
                    (merchant_user_id,),
                )
                return cur.fetchone() is not None

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

            # ====== 新增：如果商户有头像则把头像叠加到二维码中间 ======
            avatar_path = None
            try:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT avatar_path FROM users WHERE id=%s", (merchant_id,))
                        row = cur.fetchone()
                        avatar_path = row.get("avatar_path") if row else None
            except Exception:
                avatar_path = None

            if avatar_path:
                try:
                    from PIL import Image
                    import io
                    # 读取二维码图像
                    qr_im = Image.open(io.BytesIO(qrcode_bytes)).convert("RGBA")
                    # 尝试打开头像文件; avatar_path 可能是相对路径
                    from core.config import AVATAR_UPLOAD_DIR
                    av_file = AVATAR_UPLOAD_DIR / avatar_path
                    if av_file.exists():
                        av_im = Image.open(av_file).convert("RGBA")
                        # 缩放头像到二维码中心尺寸 (约1/4 宽度)
                        target_size = int(qr_im.width * 0.25)
                        av_im = av_im.resize((target_size, target_size), Image.ANTIALIAS)
                        # 计算位置并粘贴
                        pos = ((qr_im.width - target_size) // 2, (qr_im.height - target_size) // 2)
                        qr_im.paste(av_im, pos, av_im)
                        # 写回 bytes
                        buf = io.BytesIO()
                        qr_im.save(buf, format="PNG")
                        qrcode_bytes = buf.getvalue()
                except Exception as e:
                    logger.warning('merchant_qrcode_avatar_failed')
            # ==========================================

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

            # 普通可访问链接（HOST 或从 WECHAT_PAY_NOTIFY_URL 推断公开域名）
            base = settings.public_base_url
            if base:
                universal_url = f"{base}/offline?id={merchant_id}"
            else:
                universal_url = f"/offline?id={merchant_id}"
            # 与 universal 一致：普通二维码指向 /offline?id=（H5 拉起小程序）
            web_url = universal_url

            # ===== 生成普通二维码图片 =====
            normal_qrcode_data_url = None
            try:
                import qrcode, io
                qr_img = qrcode.make(web_url)
                buf = io.BytesIO()
                qr_img.save(buf, format="PNG")
                normal_qrcode_b64 = base64.b64encode(buf.getvalue()).decode()
                normal_qrcode_data_url = f"data:image/png;base64,{normal_qrcode_b64}"
            except Exception as e:
                logger.warning('merchant_qrcode_render_failed')
            # =================================

            return {
                "qrcode": qrcode_data_url,                  # 小程序码 / 太阳码
                "url": web_url,                             # 传统二维码指向的页面
                "universal_link": universal_url,           # 兼容旧客户端/描述
                "plain_qrcode": normal_qrcode_data_url,    # base64 PNG 普通二维码
                "expire_at": None,  # 永久有效
                "merchant_id": merchant_id
            }
        except Exception as e:
            logger.error('merchant_qrcode_failed')
            raise

    # ==============================================================

    # ==================== 新增：用户创建订单（永久码场景） ====================
    @staticmethod
    async def create_order_for_user(merchant_id: int, user_id: int, amount: int,
                                    coupon_id: Optional[int] = None,
                                    coupon_ids: Optional[list[int]] = None) -> str:
        """
        创建订单（不生成二维码），用于永久码场景。
        :param merchant_id: 商家ID
        :param user_id: 用户ID
        :param amount: 订单金额（分）
        :param coupon_id: 优惠券ID（可选，兼容单券）
        :param coupon_ids: 多张优惠券ID（可选）
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
        merged = OfflineService._merge_offline_coupon_ids(coupon_ids=coupon_ids, coupon_id=coupon_id)
        primary = merged[0] if merged else None
        coupon_ids_json = json.dumps(merged) if merged else None
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 插入订单，状态为待支付（1）
                cur.execute("""
                    INSERT INTO offline_order
                    (order_no, merchant_id, user_id, amount, coupon_id, coupon_ids, store_name, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 1)
                """, (order_no, merchant_id, user_id, amount, primary, coupon_ids_json, store_name))
                conn.commit()
        return order_no
    # ==============================================================