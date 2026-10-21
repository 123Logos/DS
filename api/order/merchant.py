from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, field_validator, StringConstraints
from typing import Optional, List, Dict, Any, Annotated
from core.database import get_conn
from core.config import settings
from services.finance_service import get_balance, withdraw
from decimal import Decimal
from .refund import RefundManager
from core.logging import get_logger
from core.auth import get_current_user, require_platform_admin

router = APIRouter()
logger = get_logger(__name__)


class MerchantManager:
    @staticmethod
    def list_orders(status: Optional[str] = None, limit: int = 50, merchant_id: Optional[int] = None) -> List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT COLUMN_NAME 
                    FROM information_schema.COLUMNS 
                    WHERE TABLE_SCHEMA = DATABASE() 
                    AND TABLE_NAME = 'users' 
                    AND COLUMN_NAME = 'phone'
                """)
                has_phone = cur.fetchone() is not None

                if has_phone:
                    sql = """SELECT o.*, u.name AS user_name, COALESCE(u.phone, '') AS user_phone
                             FROM orders o JOIN users u ON o.user_id=u.id"""
                else:
                    sql = """SELECT o.*, u.name AS user_name, NULL AS user_phone
                             FROM orders o JOIN users u ON o.user_id=u.id"""

                params = []
                if status:
                    sql += " WHERE o.status=%s"
                    params.append(status)
                if merchant_id is not None:
                    sql += " AND" if status else " WHERE"
                    sql += " o.merchant_id=%s"
                    params.append(merchant_id)
                sql += " ORDER BY o.created_at DESC LIMIT %s"
                params.append(limit)
                cur.execute(sql, tuple(params))
                orders = cur.fetchall()
                for o in orders:
                    cur.execute("""SELECT oi.*, p.name AS product_name
                                   FROM order_items oi JOIN products p ON oi.product_id=p.id
                                   WHERE oi.order_id=%s""", (o["id"],))
                    o["items"] = cur.fetchall()
                return orders

    @staticmethod
    def ship(
            order_number: str,
            tracking_number: Optional[str] = None,
            express_company: Optional[str] = None,
            logistics_type: Optional[int] = None,
            item_desc: Optional[str] = None
    ) -> Dict[str, Any]:
        result = {"ok": False, "local_updated": False, "message": ""}

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT o.*, u.openid, u.mobile as user_phone, u.name as user_name,
                              o.delivery_way, o.transaction_id, o.consignee_phone
                       FROM orders o 
                       JOIN users u ON o.user_id = u.id 
                       WHERE o.order_number=%s""",
                    (order_number,)
                )
                order_info = cur.fetchone()

                if not order_info:
                    result["message"] = "订单不存在"
                    return result

                if order_info["status"] != "pending_ship":
                    result["message"] = f"订单状态不正确，当前状态：{order_info['status']}"
                    return result

                delivery_way = order_info.get("delivery_way", "platform")

                if logistics_type is None:
                    logistics_map = {"platform": 1, "express": 1, "pickup": 4, "same_city": 2, "virtual": 3}
                    logistics_type = logistics_map.get(delivery_way, 1)

                is_self_pickup = (logistics_type == 4) or (delivery_way == "pickup")
                is_virtual = (logistics_type == 3)

                if not is_self_pickup and not is_virtual:
                    if not tracking_number:
                        result["message"] = "实体物流订单必须填写物流单号"
                        return result
                    tracking_trimmed = (tracking_number or "").strip()
                    if not tracking_trimmed or len(tracking_trimmed) < 6 or len(tracking_trimmed) > 32:
                        result["message"] = "物流单号长度不符合要求(6-32位)"
                        return result
                    tracking_number = tracking_trimmed

                    if not express_company:
                        express_company = "YTO"
                        logger.info("订单%s实体物流未传快递公司，已兜底为 YTO", order_number)
                    else:
                        express_company = express_company.strip().upper()

                actual_tracking = tracking_number
                if not actual_tracking:
                    if is_self_pickup:
                        actual_tracking = "用户自提"
                    elif is_virtual:
                        actual_tracking = "虚拟商品"
                    else:
                        actual_tracking = ""

                cur.execute(
                    "UPDATE orders SET status='pending_recv', tracking_number=%s "
                    "WHERE order_number=%s AND status='pending_ship'",
                    (actual_tracking, order_number)
                )
                conn.commit()

                updated = cur.rowcount > 0
                result["local_updated"] = updated

                if not updated:
                    result["message"] = "更新订单状态失败"
                    return result

                result["ok"] = True
                result["message"] = "发货成功"

                # ===== 同步发货信息到微信 =====
                try:
                    transaction_id = order_info.get("transaction_id")
                    openid = order_info.get("openid")
                    if transaction_id and openid:
                        from services.wechat_shipping_v2_service import WechatShippingService, LOGISTICS_TYPE_MAP
                        wx_service = WechatShippingService()

                        # 查询订单商品名称，构造 item_desc
                        with get_conn() as inner_conn:  # 独立连接，不影响外层事务
                            with inner_conn.cursor() as inner_cur:
                                inner_cur.execute("""
                                    SELECT p.name
                                    FROM order_items oi
                                    JOIN products p ON oi.product_id = p.id
                                    WHERE oi.order_id = %s
                                """, (order_info['id'],))
                                products = inner_cur.fetchall()

                        logger.info(f"订单 {order_number} 商品名称: {[p['name'] for p in products]}")

                        # 清理特殊字符并拼接商品名
                        import re
                        clean_names = [re.sub(r'[\r\n\t]', '', p['name']) for p in products]
                        joined = '、'.join(clean_names)
                        if len(joined) > 120:
                            item_desc = joined[:117] + "…"
                        else:
                            item_desc = joined
                        if not item_desc:
                            item_desc = "商品"
                        # 确保UTF8编码
                        item_desc = item_desc.encode('utf-8').decode('utf-8')

                        # 物流类型映射
                        wx_logistics_type = LOGISTICS_TYPE_MAP.get(delivery_way, 1)

                        # 快递公司编码映射（常见中文名称）
                        express_mapping = {
                            "圆通": "YTO", "韵达": "YUNDA", "中通": "ZTO", "申通": "STO",
                            "顺丰": "SF", "京东": "JD", "邮政": "EMS", "极兔": "JTSD"
                        }
                        company = express_company or "YTO"
                        if company in express_mapping:
                            company = express_mapping[company]
                        company = company.upper()

                        shipping_list = [{"item_desc": item_desc}]
                        if wx_logistics_type in [1, 2]:  # 快递或同城配送需填写物流单号
                            shipping_list[0]["tracking_no"] = actual_tracking
                            shipping_list[0]["express_company"] = company

                        wx_result = wx_service.upload_shipping_info(
                            transaction_id=transaction_id,
                            openid=openid,
                            logistics_type=wx_logistics_type,
                            shipping_list=shipping_list,
                            delivery_mode=1
                        )

                        if wx_result.get("errcode") == 0:
                            logger.info(f"订单 {order_number} 发货信息同步微信成功")
                        else:
                            logger.error(f"订单 {order_number} 发货信息同步微信失败: {wx_result}")
                    else:
                        logger.warning(f"订单 {order_number} 缺少 transaction_id 或 openid，无法同步微信发货")
                except Exception as e:
                    logger.error(f"订单 {order_number} 调用微信发货接口异常: {e}", exc_info=True)
                # ===================================

                return result

    @staticmethod
    def wx_remind_confirm_receive(order_number: str, received_time: int) -> Dict[str, Any]:
        """调用微信「确认收货提醒」接口（官方限制：仅实体快递 logistics_type=1，每单一次）。"""
        out: Dict[str, Any] = {"ok": False, "message": "", "wechat": {}}
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT o.id, o.order_number, o.status, o.transaction_id, o.delivery_way
                       FROM orders o WHERE o.order_number=%s""",
                    (order_number,),
                )
                row = cur.fetchone()
                if not row:
                    out["message"] = "订单不存在"
                    return out
                if row["status"] != "pending_recv":
                    out["message"] = f"订单状态须为待收货，当前：{row['status']}"
                    return out
                tx = (row.get("transaction_id") or "").strip()
                if not tx:
                    out["message"] = "订单无微信支付 transaction_id，无法调用微信接口"
                    return out

        from services.wechat_shipping_v2_service import WechatShippingService

        wx = WechatShippingService()
        info = wx.get_order_response(tx)
        out["wechat_query"] = info
        if info.get("errcode") != 0:
            out["message"] = f"微信查询订单失败: {info.get('errmsg', info)}"
            return out
        order_wx = info.get("order") or {}
        shipping = order_wx.get("shipping") or {}
        if shipping.get("logistics_type") != 1:
            out["message"] = "微信侧非实体快递发货，官方不允许调用确认收货提醒"
            return out

        mchid = (getattr(settings, "WECHAT_PAY_MCH_ID", None) or "").strip() or None
        wx_ret = wx.notify_confirm_receive(
            tx,
            received_time,
            merchant_id=mchid,
            merchant_trade_no=order_number,
        )
        out["wechat"] = wx_ret
        if wx_ret.get("errcode") == 0:
            out["ok"] = True
            out["message"] = "已请求微信提醒用户确认收货"
        else:
            out["message"] = wx_ret.get("errmsg") or str(wx_ret)
        return out

    @staticmethod
    def wx_set_shipping_msg_jump_path(path: str) -> Dict[str, Any]:
        """设置发货/确认收货订阅消息点击后跳转的小程序页面（官方 set_msg_jump_path）。"""
        from services.wechat_shipping_v2_service import WechatShippingService

        wx = WechatShippingService()
        r = wx.set_msg_jump_path(path)
        if r.get("errcode") == 0:
            return {"ok": True, "wechat": r}
        return {"ok": False, "message": r.get("errmsg") or str(r), "wechat": r}

    @staticmethod
    def approve_refund(order_number: str, approve: bool = True, reject_reason: Optional[str] = None):
        RefundManager.audit(order_number, approve, reject_reason)


class MShip(BaseModel):
    order_number: str
    tracking_number: Optional[str] = None
    express_company: Optional[str] = None
    logistics_type: Optional[int] = None
    item_desc: Optional[str] = None
    # 扫码枪/电子面单复制的一整段；与 tracking_number / express_company 合并，显式传入的字段优先
    scan_text: Optional[str] = None


class MShipScanParse(BaseModel):
    raw: str


class MRefundAudit(BaseModel):
    order_number: str
    approve: bool
    reject_reason: Optional[str] = None


class MWxRemindConfirmReceive(BaseModel):
    order_number: str
    received_time: Optional[int] = None


class MWxShippingMsgJumpPath(BaseModel):
    path: str


class MWithdraw(BaseModel):
    amount: float


class MBindBank(BaseModel):
    user_id: int
    bank_name: str
    bank_account: Annotated[str, StringConstraints(strip_whitespace=True, min_length=10, max_length=30)]

    @field_validator("bank_account")
    @classmethod
    def digits_only(cls, v: str) -> str:
        if not v.isdigit():
            raise ValueError("银行卡号只能为数字")
        return v


@router.get("/orders", summary="查询订单列表")
def m_orders(status: Optional[str] = None, current_user: dict = Depends(get_current_user)):
    merchant_id = None if str(current_user.get("id")) in settings.ADMIN_USER_IDS.split(",") else current_user.get("id")
    return MerchantManager.list_orders(status, merchant_id=merchant_id)


@router.post("/wx/remind-confirm-receive", summary="微信官方-提醒用户确认收货（仅快递，每单一次）")
def m_wx_remind_confirm_receive(body: MWxRemindConfirmReceive, _: dict = Depends(require_platform_admin)):
    import time as time_mod

    ts = body.received_time if body.received_time is not None else int(time_mod.time())
    result = MerchantManager.wx_remind_confirm_receive(body.order_number, ts)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("message") or "调用失败")
    return result


@router.post("/wx/shipping-msg-jump-path", summary="微信官方-设置发货/确认收货消息跳转小程序路径")
def m_wx_shipping_msg_jump_path(body: MWxShippingMsgJumpPath, _: dict = Depends(require_platform_admin)):
    result = MerchantManager.wx_set_shipping_msg_jump_path(body.path)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result.get("message") or "设置失败")
    return result


@router.post("/ship/parse-scan", summary="解析扫码/面单文本为运单号与快递公司（仅解析，不写入）")
def m_ship_parse_scan(body: MShipScanParse, _: dict = Depends(get_current_user)):
    from services.logistics_scan_parse import parse_ship_scan

    return {"ok": True, "data": parse_ship_scan(body.raw)}


@router.post("/ship", summary="订单发货")
def m_ship(body: MShip, current_user: dict = Depends(get_current_user)):
    tracking_number = body.tracking_number
    express_company = body.express_company
    if body.scan_text:
        from services.logistics_scan_parse import parse_ship_scan

        parsed = parse_ship_scan(body.scan_text)
        tracking_number = tracking_number or parsed.get("tracking_number")
        express_company = express_company or parsed.get("express_company")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT merchant_id FROM orders WHERE order_number=%s", (body.order_number,))
            order = cur.fetchone()
    if not order or (str(current_user.get("id")) not in settings.ADMIN_USER_IDS.split(",")
                     and order.get("merchant_id") != current_user.get("id")):
        raise HTTPException(status_code=403, detail="无权操作该订单")
    result = MerchantManager.ship(
        order_number=body.order_number,
        tracking_number=tracking_number,
        express_company=express_company,
        logistics_type=body.logistics_type,
        item_desc=body.item_desc
    )
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@router.post("/approve_refund", summary="审核退款申请")
def m_refund_audit(body: MRefundAudit, current_user: dict = Depends(get_current_user)):
    if str(current_user.get("id")) not in settings.ADMIN_USER_IDS.split(","):
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT merchant_id FROM orders WHERE order_number=%s", (body.order_number,))
                order = cur.fetchone()
        if not order or order.get("merchant_id") != current_user.get("id"):
            raise HTTPException(status_code=403, detail="无权审核该订单")
    MerchantManager.approve_refund(body.order_number, body.approve, body.reject_reason)
    return {"ok": True}


@router.post("/withdraw", summary="申请提现", operation_id="merchant_withdraw")
def m_withdraw(body: MWithdraw, _: dict = Depends(get_current_user)):
    ok = withdraw(Decimal(str(body.amount)))
    if not ok:
        raise HTTPException(status_code=400, detail="余额不足")
    return {"ok": True}


@router.post("/bind_bank", summary="绑定银行卡", operation_id="merchant_bind_bank")
def m_bind(body: MBindBank, current_user: dict = Depends(get_current_user)):
    if str(current_user.get("id")) not in settings.ADMIN_USER_IDS.split(",") and body.user_id != current_user.get("id"):
        raise HTTPException(status_code=403, detail="只能操作本人银行卡")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM users WHERE id=%s LIMIT 1", (body.user_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="用户不存在")
            cur.execute(
                "SELECT id FROM user_bankcards WHERE user_id=%s AND bank_account=%s LIMIT 1",
                (body.user_id, body.bank_account)
            )
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="该银行卡已绑定，无需重复绑定")
            cur.execute(
                "INSERT INTO user_bankcards (user_id, bank_name, bank_account) VALUES (%s, %s, %s)",
                (body.user_id, body.bank_name, body.bank_account)
            )
            conn.commit()
    return {"ok": True}