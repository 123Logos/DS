from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime
from core.database import get_conn
from core.table_access import build_dynamic_select
from services.finance_service import reverse_split_on_refund
from core.wx_pay_client import wxpay_client
from core.config import settings
from core.logging import get_logger

logger = get_logger(__name__)

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
    def audit(
        order_number: str,
        approve: bool = True,
        reject_reason: Optional[str] = None,
        merchant_address: Optional[str] = None
    ) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:

                # 1. 查询退款类型
                cur.execute(
                    "SELECT refund_type FROM refunds WHERE order_number=%s",
                    (order_number,)
                )
                row = cur.fetchone()
                if not row:
                    return False

                refund_type = row["refund_type"]

                # 2. 仅「同意 + 退货退款」才强制要求地址
                if approve and refund_type == "return_refund":
                    if not merchant_address:
                        raise HTTPException(
                            status_code=400,
                            detail="同意退货退款时必须填写商家地址"
                        )

                if approve:
                    # ---------- 调用微信退款接口 ----------
                    # 获取订单支付信息
                    cur.execute(
                        "SELECT transaction_id, total_amount FROM orders WHERE order_number=%s",
                        (order_number,)
                    )
                    order_info = cur.fetchone()
                    if not order_info or not order_info['transaction_id']:
                        raise HTTPException(status_code=400, detail="订单无微信交易号，无法退款")

                    transaction_id = order_info['transaction_id']
                    total_fee = int(order_info['total_amount'] * 100)   # 转为分
                    refund_fee = total_fee   # 全额退款

                    # 生成商户退款单号（唯一）
                    out_refund_no = f"REF{order_number}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    try:
                        refund_result = wxpay_client.refund(
                            transaction_id=transaction_id,
                            out_refund_no=out_refund_no,
                            total_fee=total_fee,
                            refund_fee=refund_fee,
                            notify_url=f"{settings.HOST.rstrip('/')}/api/wechat-pay/refund-notify"
                        )
                        logger.info(f"微信退款受理成功: {refund_result}")
                    except Exception as e:
                        logger.error(f"微信退款失败: {e}")
                        raise HTTPException(status_code=500, detail=f"微信退款调用失败: {e}")

                    # ---------- 将退款单号存入订单表（便于回调时匹配）----------
                    # 如果 orders 表没有 refund_no 字段，可先添加；这里假设已存在
                    cur.execute(
                        "UPDATE orders SET refund_no=%s WHERE order_number=%s",
                        (out_refund_no, order_number)
                    )

                    # ---------- 内部资金回冲 ----------
                    reverse_split_on_refund(order_number)

                    # ---------- 更新订单状态为退款中 ----------
                    cur.execute(
                        "UPDATE orders SET status='refunding' WHERE order_number=%s",
                        (order_number,)
                    )
                else:
                    # 拒绝退款：只更新退款状态为 rejected，订单主状态保持不变
                    new_status = "rejected"
                    cur.execute(
                        """
                        UPDATE refunds
                        SET status=%s,
                            reject_reason=%s,
                            merchant_address=%s
                        WHERE order_number=%s
                        """,
                        (new_status, reject_reason, merchant_address, order_number)
                    )
                    if cur.rowcount == 0:
                        return False

                    # 回写订单退款状态
                    cur.execute(
                        "UPDATE orders SET refund_status=%s WHERE order_number=%s",
                        (new_status, order_number)
                    )
                    # ⚠️ 移除错误地将订单主状态改为 completed 的语句

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
    refund_type: str
    reason_code: str


class RefundAudit(BaseModel):
    order_number: str
    approve: bool
    reject_reason: Optional[str] = None
    merchant_address: Optional[str] = None


# ---------------- 路由 ----------------
@router.post("/apply", summary="申请退款")
def refund_apply(body: RefundApply):
    ok = RefundManager.apply(body.order_number, body.refund_type, body.reason_code)
    if not ok:
        raise HTTPException(status_code=400, detail="该订单已申请过退款")
    return {"ok": True}


@router.post("/audit", summary="审核退款申请")
def refund_audit(body: RefundAudit):
    RefundManager.audit(
        body.order_number,
        body.approve,
        body.reject_reason,
        body.merchant_address
    )
    return {"ok": True}


@router.get("/progress/{order_number}", summary="查询退款进度")
def refund_progress(order_number: str):
    return RefundManager.progress(order_number) or {}