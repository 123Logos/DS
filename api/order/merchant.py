from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator, StringConstraints
from typing import Optional, List, Dict, Any, Annotated
from core.database import get_conn
from services.finance_service import get_balance, withdraw   # 不再用 bind_bank
from decimal import Decimal
from .refund import RefundManager

router = APIRouter()

class MerchantManager:
    @staticmethod
    def list_orders(status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查 users 表是否有 phone 字段
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
    def ship(order_number: str, tracking_number: str) -> bool:
        """
        发货：写入快递单号并把状态改为 pending_recv
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE orders SET status='pending_recv', tracking_number=%s "
                    "WHERE order_number=%s AND status='pending_ship'",
                    (tracking_number, order_number)
                )
                conn.commit()
                return cur.rowcount > 0

    @staticmethod
    def approve_refund(order_number: str, approve: bool = True, reject_reason: Optional[str] = None):
        RefundManager.audit(order_number, approve, reject_reason)

# ---------------- 路由 ----------------
class MShip(BaseModel):
    order_number: str
    tracking_number: str

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
    ok = MerchantManager.ship(body.order_number, body.tracking_number)
    return {"ok": ok}

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