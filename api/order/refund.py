from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional
from core.database import get_conn
from core.table_access import build_dynamic_select
from services.finance_service import reverse_split_on_refund
from typing import Dict, Any

router = APIRouter()

class RefundManager:
    @staticmethod
    def apply(order_number: str, refund_type: str, reason_code: str) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur,
                    "refunds",
                    where_clause="order_number=%s",
                    select_fields=["id"]
                )
                cur.execute(select_sql, (order_number,))
                if cur.fetchone():
                    return False
                cur.execute("""INSERT INTO refunds(order_number,refund_type,reason,status)
                               VALUES(%s,%s,%s,'applied')""", (order_number, refund_type, reason_code))
                conn.commit()
                return True

    @staticmethod
    def audit(order_number: str, approve: bool = True, reject_reason: Optional[str] = None) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                new_status = "success" if approve else "rejected"
                cur.execute("UPDATE refunds SET status=%s,reject_reason=%s WHERE order_number=%s",
                            (new_status, reject_reason, order_number))
                if approve:
                    cur.execute("UPDATE orders SET status='refund' WHERE order_number=%s", (order_number,))
                    reverse_split_on_refund(order_number)
                conn.commit()
                return True

    @staticmethod
    def progress(order_number: str) -> Optional[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur,
                    "refunds",
                    where_clause="order_number=%s"
                )
                cur.execute(select_sql, (order_number,))
                return cur.fetchone()

# ---------------- 路由 ----------------
class RefundApply(BaseModel):
    order_number: str
    refund_type: str
    reason_code: str

class RefundAudit(BaseModel):
    order_number: str
    approve: bool
    reject_reason: Optional[str] = None

@router.post("/apply", summary="申请退款")
def refund_apply(body: RefundApply):
    ok = RefundManager.apply(body.order_number, body.refund_type, body.reason_code)
    if not ok:
        raise HTTPException(status_code=400, detail="该订单已申请过退款")
    return {"ok": True}

@router.post("/audit", summary="审核退款申请")
def refund_audit(body: RefundAudit):
    RefundManager.audit(body.order_number, body.approve, body.reject_reason)
    return {"ok": True}

@router.get("/progress/{order_number}", summary="查询退款进度")
def refund_progress(order_number: str):
    return RefundManager.progress(order_number) or {}
