from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any, Literal
from core.database import get_conn
from core.table_access import build_dynamic_select
from core.logging import get_logger
from core.auth import (
    get_current_user,
    require_admin_or_merchant,
    require_platform_admin,
    is_platform_admin,
)

logger = get_logger(__name__)

router = APIRouter()


class RefundManager:
    @staticmethod
    def apply(order_number: str, refund_type: str, reason_code: str, user_id: int) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT status FROM orders WHERE order_number=%s AND user_id=%s FOR UPDATE",
                    (order_number, user_id),
                )
                order = cur.fetchone()
                if not order or order["status"] not in ("pending_ship", "pending_recv", "completed"):
                    return False
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
    def audit(order_number: str, approve: bool = True, reject_reason=None,
              merchant_address=None, current_user=None) -> bool:
        from services.refund_service import RefundService
        if current_user is None:
            raise HTTPException(401, "需要认证身份")
        if approve:
            RefundService.request(order_number, current_user, audit=True, merchant_address=merchant_address)
            return True
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT merchant_id,status FROM orders WHERE order_number=%s FOR UPDATE", (order_number,))
                order = cur.fetchone()
                if not order or (not is_platform_admin(current_user) and int(order.get('merchant_id') or 0) != int(current_user['id'])):
                    raise HTTPException(403, "无权审核该退款")
                if order['status'] == 'refunding':
                    raise HTTPException(409, "退款已提交不可拒绝")
                cur.execute("UPDATE refunds SET status='rejected',reject_reason=%s WHERE order_number=%s AND status='applied'", (reject_reason, order_number))
                if cur.rowcount != 1:
                    raise HTTPException(409, "申请状态已变化")
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


# ---------------- 请求模型 ----------------
class RefundApply(BaseModel):
    order_number: str
    refund_type: Literal['return', 'refund_only']
    reason_code: str


class RefundAudit(BaseModel):
    order_number: str
    approve: bool
    reject_reason: Optional[str] = None
    merchant_address: Optional[str] = None


# ---------------- 路由 ----------------
@router.post("/apply", summary="申请退款")
def refund_apply(body: RefundApply, current_user: dict = Depends(get_current_user)):
    logger.info(f"🔥 申请退款接口被调用: order_number={body.order_number}, refund_type={body.refund_type}, reason={body.reason_code}")
    ok = RefundManager.apply(
        body.order_number, body.refund_type, body.reason_code, int(current_user["id"])
    )
    if not ok:
        logger.warning(f"申请退款失败: 订单 {body.order_number} 已申请过退款")
        raise HTTPException(status_code=400, detail="该订单已申请过退款")
    logger.info(f"申请退款成功: 订单 {body.order_number} 已记录，等待审核")
    return {"ok": True}


@router.post("/audit", summary="审核退款申请")
def refund_audit(
    body: RefundAudit,
    current_user: dict = Depends(require_admin_or_merchant),
):
    logger.info(f"🔥 退款审核接口被调用: order_number={body.order_number}, approve={body.approve}")
    RefundManager.audit(
        body.order_number,
        body.approve,
        body.reject_reason,
        body.merchant_address, current_user=current_user
    )
    return {"ok": True}


@router.get("/progress/{order_number}", summary="查询退款进度")
def refund_progress(order_number: str, current_user: dict = Depends(get_current_user)):
    result = RefundManager.progress(order_number) or {}
    if not result:
        return {}
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id, merchant_id FROM orders WHERE order_number=%s", (order_number,))
            order = cur.fetchone()
    if not order or (
        not is_platform_admin(current_user)
        and int(current_user["id"]) not in {int(order.get("user_id") or 0), int(order.get("merchant_id") or 0)}
    ):
        raise HTTPException(status_code=403, detail="无权查看该退款")
    return result

# ==================== 新增：退款查询接口 ====================

@router.get("/query/{order_number}", summary="查询退款状态")
def query_refund_status(order_number: str, current_user: dict = Depends(get_current_user)):
    """
    查询订单退款状态（包括微信侧状态）
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """SELECT id, user_id, merchant_id, status, refund_no, transaction_id, total_amount,
                          created_at, updated_at
                   FROM orders WHERE order_number=%s""",
                (order_number,)
            )
            order = cur.fetchone()
            
            if not order:
                raise HTTPException(status_code=404, detail="订单不存在")
            allowed = (
                is_platform_admin(current_user)
                or int(current_user["id"]) == int(order.get("user_id") or 0)
                or int(current_user["id"]) == int(order.get("merchant_id") or 0)
            )
            if not allowed:
                raise HTTPException(status_code=403, detail="无权查看该退款")
            
            flows = []
            
            # 查询退款申请表
            cur.execute(
                """SELECT id, refund_type, reason, status, reject_reason, created_at, updated_at 
                   FROM refunds WHERE order_number=%s""",
                (order_number,)
            )
            refund_apply = cur.fetchone()
    
    return {
        "order_number": order_number,
        "order_status": order.get('status'),
        "refund_no": order.get('refund_no'),
        "transaction_id": order.get('transaction_id'),
        "total_amount": float(order.get('total_amount', 0)),
        "created_at": order.get('created_at'),
        "updated_at": order.get('updated_at'),
        "refund_apply": refund_apply,
        "account_flows": [
            {
                "account_type": f['account_type'],
                "change_amount": float(f['change_amount']),
                "flow_type": f['flow_type'],
                "remark": f['remark'],
                "created_at": f['created_at']
            } for f in flows
        ] if flows else [],
        "wechat_status_note": "如需查询微信侧实时状态，请登录微信商户平台"
    }


@router.post("/sync-status/{order_number}", summary="同步微信退款状态（手动）")
def sync_refund_status(order_number: str, current_user: dict = Depends(require_platform_admin)):
    """
    手动同步微信退款状态（当回调未收到时使用）
    """
    from services.refund_service import RefundService
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT out_refund_no FROM payment_refund_intents WHERE order_number=%s ORDER BY id DESC LIMIT 1", (order_number,))
            row = cur.fetchone()
    if not row:
        raise HTTPException(404, "退款意图不存在，历史退款需要人工对账接管")
    return RefundService.recover(row['out_refund_no'])

@router.get('/reconciliation/cases', summary='平台支付退款待对账清单')
def reconciliation_cases(current_user: dict = Depends(require_platform_admin)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT case_key,order_number,transaction_id,total_fee,refund_no,reason,state,created_at FROM payment_reconciliation_cases WHERE state='open' ORDER BY created_at LIMIT 200")
            return {'items': cur.fetchall()}