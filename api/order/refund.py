from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from core.database import get_conn
from core.table_access import build_dynamic_select
from services.finance_service import reverse_split_on_refund
from core.wx_pay_client import wxpay_client
from core.config import settings
from core.logging import get_logger
from core.auth import (
    get_current_user,
    require_admin_or_merchant,
    require_platform_admin,
    is_platform_admin,
)
from decimal import Decimal
from services.finance_service import FinanceService, reverse_split_on_refund

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
    def audit(
        order_number: str,
        approve: bool = True,
        reject_reason: Optional[str] = None,
        merchant_address: Optional[str] = None
    ) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                
                logger.info(f"【退款审核】开始处理订单: {order_number}, 审核结果: {approve}")

                # 1. 查询退款类型
                cur.execute(
                    "SELECT refund_type FROM refunds WHERE order_number=%s",
                    (order_number,)
                )
                row = cur.fetchone()
                if not row:
                    logger.error(f"【退款审核】未找到退款记录: {order_number}")
                    return False

                refund_type = row["refund_type"]
                logger.info(f"【退款审核】退款类型: {refund_type}")

                # 2. 仅「同意 + 退货退款」才强制要求地址
                if approve and refund_type == "return_refund":
                    if not merchant_address:
                        logger.error(f"【退款审核】缺少商家地址: {order_number}")
                        raise HTTPException(
                            status_code=400,
                            detail="同意退货退款时必须填写商家地址"
                        )

                if approve:
                    # ---------- 获取订单和商户信息 ----------
                    cur.execute(
                        """SELECT o.id, o.transaction_id, o.total_amount, o.status, 
                                o.refund_no, o.merchant_id, u.wechat_sub_mchid 
                        FROM orders o 
                        LEFT JOIN users u ON o.merchant_id = u.id 
                        WHERE o.order_number=%s""",
                        (order_number,)
                    )
                    order_info = cur.fetchone()
                    if not order_info:
                        logger.error(f"【退款审核】订单不存在: {order_number}")
                        raise HTTPException(status_code=400, detail="订单不存在")

                    # 判断是否零元订单
                    from decimal import Decimal
                    total_amount = Decimal(str(order_info.get('total_amount') or 0))
                    is_zero_order = (total_amount <= 0)

                    # 状态校验
                    if order_info.get('status') not in ['pending_ship', 'pending_recv', 'completed', 'refunding']:
                        logger.error(f"【退款审核】订单状态不允许退款: {order_info.get('status')}")
                        raise HTTPException(status_code=400, detail=f"订单状态 {order_info.get('status')} 不允许退款")

                    # 防重复退款
                    current_status = order_info.get('status')
                    existing_refund_no = order_info.get('refund_no')
                    if current_status == 'refunded':
                        logger.warning(f"【退款审核】订单已退款，拒绝重复申请: {order_number}, 退款单号: {existing_refund_no}")
                        raise HTTPException(status_code=400, detail="该订单已退款完成，不能重复退款")
                    if current_status == 'refunding':
                        logger.error(f"【退款审核】订单已在退款中，拒绝重复申请: {order_number}, 已有退款单号: {existing_refund_no}")
                        raise HTTPException(
                            status_code=400,
                            detail=f"该订单正在退款处理中（退款单号：{existing_refund_no}），请勿重复提交。如长时间未到账，请联系客服处理。"
                        )

                    # ========== 零元订单特殊处理 ==========
                    if is_zero_order:
                        logger.info(f"【退款审核】检测到零元订单 {order_number}，跳过微信退款接口，直接执行内部回退")
                        try:
                            import time
                            out_refund_no = f"ZERO_REFUND_{order_number}_{int(time.time())}"
                            cur.execute(
                                "UPDATE orders SET refund_no=%s WHERE order_number=%s",
                                (out_refund_no, order_number)
                            )
                            logger.info(f"【退款审核】零元订单已生成退款单号: {out_refund_no}")

                            # ✅ 注意：reverse_split_on_refund 内部会使用 get_conn()，但它是独立连接，不影响当前事务
                            # 这里直接调用即可，它内部会自己管理连接
                            reverse_split_on_refund(order_number)

                            # 更新订单状态为 refunded
                            cur.execute(
                                "UPDATE orders SET status='refunded', updated_at=NOW() WHERE order_number=%s",
                                (order_number,)
                            )
                            logger.info(f"【退款审核】零元订单状态已更新为 refunded")

                            # 更新退款申请状态
                            cur.execute(
                                """UPDATE refunds
                                SET status='refund_success',
                                    merchant_address=%s
                                WHERE order_number=%s""",
                                (merchant_address, order_number)
                            )

                            conn.commit()
                            logger.info(f"【退款审核】零元订单事务已提交")

                            # 调用积分/优惠券回退（独立事务，不影响已提交的退款事务）
                            from services.finance_service import FinanceService
                            FinanceService.revoke_order_discounts(order_number)

                            logger.info(f"【退款审核】零元订单退款处理完成: {order_number}")
                            return True
                        except Exception as e:
                            logger.error(f"【退款审核】零元订单处理失败: {e}", exc_info=True)
                            conn.rollback()
                            raise HTTPException(status_code=500, detail=f"零元订单退款失败: {str(e)}")

                    # ========== 正常订单（非零元）逻辑 ==========
                    transaction_id = order_info.get('transaction_id')
                    if not transaction_id:
                        # 线下单：微信回调写在 offline_order，历史版本 on_paid 未同步到 orders
                        cur.execute(
                            "SELECT transaction_id FROM offline_order WHERE order_no=%s LIMIT 1",
                            (order_number,),
                        )
                        off = cur.fetchone()
                        if off and off.get("transaction_id"):
                            transaction_id = off["transaction_id"]
                            cur.execute(
                                """UPDATE orders SET transaction_id=%s
                                   WHERE order_number=%s
                                   AND (transaction_id IS NULL OR transaction_id='')""",
                                (transaction_id, order_number),
                            )
                            logger.info(
                                f"【退款审核】已从 offline_order 补全微信交易号并回写 orders: {order_number}"
                            )
                    if not transaction_id:
                        logger.error(f"【退款审核】订单无微信交易号，无法退款。订单状态: {order_info.get('status')}")
                        raise HTTPException(status_code=400, detail="订单未支付或缺少微信交易号，无法退款")

                    total_fee = int(round(float(order_info['total_amount']) * 100))
                    refund_fee = total_fee
                    if total_fee <= 0:
                        logger.error(f"【退款审核】订单金额无效: {total_fee}")
                        raise HTTPException(status_code=400, detail="订单金额无效，无法退款")

                    sub_mchid = order_info.get('wechat_sub_mchid')
                    out_refund_no = f"REF{order_number}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    logger.info(f"【退款审核】退款单号: {out_refund_no}, 金额: {refund_fee}分")

                    # 调用微信退款
                    try:
                        refund_result = wxpay_client.refund(
                            transaction_id=transaction_id,
                            out_refund_no=out_refund_no,
                            total_fee=total_fee,
                            refund_fee=refund_fee,
                            notify_url=f"{settings.public_base_url}/api/wechat-pay/refund-notify",
                            sub_mchid=sub_mchid
                        )
                        logger.info(f"【退款审核】微信退款受理成功: {refund_result}")
                    except Exception as e:
                        logger.error(f"【退款审核】微信退款调用失败: {e}", exc_info=True)
                        raise HTTPException(status_code=500, detail=f"微信退款调用失败: {str(e)}")

                    cur.execute(
                        "UPDATE orders SET refund_no=%s WHERE order_number=%s",
                        (out_refund_no, order_number)
                    )
                    reverse_split_on_refund(order_number)
                    cur.execute(
                        "UPDATE orders SET status='refunding' WHERE order_number=%s",
                        (order_number,)
                    )
                    # 更新退款申请状态为“卖家同意”
                    cur.execute(
                        """UPDATE refunds
                        SET status='seller_ok',
                            merchant_address=%s
                        WHERE order_number=%s""",
                        (merchant_address, order_number)
                    )
                    conn.commit()
                    logger.info(f"【退款审核】处理完成: {order_number}")
                    return True

                else:
                    # 拒绝退款
                    logger.info(f"【退款审核】拒绝退款: {order_number}, 原因: {reject_reason}")
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
                    cur.execute(
                        "UPDATE orders SET refund_status=%s WHERE order_number=%s",
                        (new_status, order_number)
                    )
                    conn.commit()
                    logger.info(f"【退款审核】处理完成: {order_number}")
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
    if not is_platform_admin(current_user):
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT merchant_id FROM orders WHERE order_number=%s",
                    (body.order_number,),
                )
                order = cur.fetchone()
        if not order or int(order.get("merchant_id") or 0) != int(current_user["id"]):
            raise HTTPException(status_code=403, detail="无权审核该订单退款")
    RefundManager.audit(
        body.order_number,
        body.approve,
        body.reject_reason,
        body.merchant_address
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
            
            # 查询资金回冲流水
            cur.execute(
                """SELECT id, account_type, change_amount, flow_type, remark, created_at 
                   FROM account_flow 
                   WHERE remark LIKE %s 
                   ORDER BY created_at DESC""",
                (f"%{order_number}%",)
            )
            flows = cur.fetchall()
            
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
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT refund_no, status FROM orders WHERE order_number=%s",
                (order_number,)
            )
            row = cur.fetchone()
            
            if not row:
                raise HTTPException(status_code=404, detail="订单不存在")
            
            if row['status'] != 'refunding':
                return {
                    "order_number": order_number,
                    "current_status": row['status'],
                    "message": "订单不在退款中状态，无需同步"
                }
            
            refund_no = row['refund_no']
            if not refund_no:
                raise HTTPException(status_code=400, detail="未找到退款单号")
    
    # 这里可以添加调用微信查询接口的逻辑
    # 暂时返回提示
    return {
        "order_number": order_number,
        "refund_no": refund_no,
        "message": "请确认微信商户平台退款状态后，如需更新请通过受控后台流程处理"
    }