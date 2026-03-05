from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, field_validator, StringConstraints
from typing import Optional, List, Dict, Any, Annotated
from core.database import get_conn
from services.finance_service import get_balance, withdraw
from decimal import Decimal
from .refund import RefundManager
from core.logging import get_logger

router = APIRouter()
logger = get_logger(__name__)


class MerchantManager:
    @staticmethod
    def list_orders(status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
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
                return result

    @staticmethod
    def approve_refund(order_number: str, approve: bool = True, reject_reason: Optional[str] = None):
        RefundManager.audit(order_number, approve, reject_reason)


class MShip(BaseModel):
    order_number: str
    tracking_number: Optional[str] = None
    express_company: Optional[str] = None
    logistics_type: Optional[int] = None
    item_desc: Optional[str] = None


class MRefundAudit(BaseModel):
    order_number: str
    approve: bool
    reject_reason: Optional[str] = None


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
def m_orders(status: Optional[str] = None):
    return MerchantManager.list_orders(status)


@router.post("/ship", summary="订单发货")
def m_ship(body: MShip):
    result = MerchantManager.ship(
        order_number=body.order_number,
        tracking_number=body.tracking_number,
        express_company=body.express_company,
        logistics_type=body.logistics_type,
        item_desc=body.item_desc
    )
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["message"])
    return result


@router.post("/approve_refund", summary="审核退款申请")
def m_refund_audit(body: MRefundAudit):
    MerchantManager.approve_refund(body.order_number, body.approve, body.reject_reason)
    return {"ok": True}


@router.post("/withdraw", summary="申请提现", operation_id="merchant_withdraw")
def m_withdraw(body: MWithdraw):
    ok = withdraw(Decimal(str(body.amount)))
    if not ok:
        raise HTTPException(status_code=400, detail="余额不足")
    return {"ok": True}


@router.post("/bind_bank", summary="绑定银行卡", operation_id="merchant_bind_bank")
def m_bind(body: MBindBank):
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