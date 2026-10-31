"""Durable refund intent; provider I/O is always outside database transactions."""
from decimal import Decimal
import uuid

from fastapi import HTTPException
from core.auth import is_platform_admin
from core.config import settings
from core.database import get_conn
from core.wx_pay_client import wxpay_client
from services.finance_service import FinanceService, reverse_split_on_refund

provider = wxpay_client


def validate_refund_fee(value, total):
    if value is None:
        return total
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0 or value > total:
        raise HTTPException(422, "refund_fee必须为不超过实付金额的正整数（分）")
    return value


class RefundService:
    @staticmethod
    def request(order_number, current_user, refund_fee=None, reason="", audit=False,
                merchant_address=None, merchant_actor=False, refund_request_id=None):
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM orders WHERE order_number=%s FOR UPDATE", (order_number,))
                order = cur.fetchone()
                if not order:
                    raise HTTPException(404, "订单不存在")
                actor = int(current_user["id"])
                owner = order.get("merchant_id") if audit or merchant_actor else order.get("user_id")
                if not is_platform_admin(current_user) and actor != int(owner or 0):
                    raise HTTPException(403, "无权操作该订单")
                cur.execute("SELECT * FROM refunds WHERE order_number=%s ORDER BY id DESC LIMIT 1 FOR UPDATE", (order_number,))
                application = cur.fetchone()
                if audit:
                    if not application:
                        raise HTTPException(404, "退款申请不存在")
                    if application['status'] not in ('applied', 'seller_ok', 'refund_success'):
                        raise HTTPException(409, '退款申请状态不允许审核')
                    if application['refund_type'] == 'return' and not merchant_address:
                        raise HTTPException(422, "同意退货退款时必须填写商家地址")
                # All entry points resolve the same active application, irrespective of client keys.
                if refund_request_id is not None and (not isinstance(refund_request_id, str) or not 1 <= len(refund_request_id) <= 64):
                    raise HTTPException(422, 'refund_request_id必须为1至64字符')
                logical_key = f"application:{application['id']}" if application else f"direct:{order_number}:{refund_request_id or 'default'}"
                cur.execute("SELECT * FROM payment_refund_intents WHERE logical_key=%s", (logical_key,))
                existing = cur.fetchone()
                if not audit:
                    cur.execute('SELECT * FROM payment_refund_intents WHERE logical_key=%s', (f"direct:{order_number}:{refund_request_id or 'default'}",))
                    original_direct = cur.fetchone()
                    if original_direct:
                        existing = original_direct
                total = int(Decimal(str(order["total_amount"])) * 100)
                fee = validate_refund_fee(refund_fee, total)
                if existing:
                    if existing["refund_fee"] != fee:
                        raise HTTPException(409, "同一退款申请金额不可变更")
                    refund_no = existing["out_refund_no"]
                else:
                    if order.get('refund_no'):
                        cur.execute('SELECT id FROM payment_refund_intents WHERE out_refund_no=%s', (order['refund_no'],))
                        if not cur.fetchone():
                            cur.execute("INSERT IGNORE INTO payment_reconciliation_cases(case_key,order_number,transaction_id,total_fee,refund_no,reason) VALUES(%s,%s,%s,%s,%s,'legacy_refund_missing_intent')", ('legacy:' + order['refund_no'], order_number, order.get('transaction_id'), total, order['refund_no']))
                            conn.commit()
                            raise HTTPException(409, '历史退款身份需对账，不得创建新退款号')
                    cur.execute('SELECT * FROM payment_merchant_transfers WHERE order_number=%s FOR UPDATE', (order_number,))
                    transfer = cur.fetchone()
                    if transfer and transfer['attempts']:
                        raise HTTPException(409, '商户转账已提交或结果未知，退款前必须对账')
                    if transfer:
                        cur.execute("UPDATE payment_merchant_transfers SET state='held',original_amount=COALESCE(original_amount,amount) WHERE order_number=%s", (order_number,))
                    if order["status"] not in ("pending_ship", "pending_recv", "completed"):
                        raise HTTPException(409, "订单状态不允许退款")
                    cur.execute("SELECT COALESCE(SUM(refund_fee),0) AS reserved FROM payment_refund_intents WHERE order_number=%s AND state NOT IN ('closed')", (order_number,))
                    if int(cur.fetchone()["reserved"]) + fee > total:
                        raise HTTPException(409, "退款累计金额超过实付金额")
                    if total and not order.get("transaction_id"):
                        raise HTTPException(409, "订单缺少支付流水，需对账")
                    # JSAPI payments in this application are direct merchant transactions.
                    refund_no = "RF" + uuid.uuid4().hex
                    cur.execute("""INSERT INTO payment_refund_intents
                        (order_number,logical_key,out_refund_no,transaction_id,total_fee,refund_fee,previous_status)
                        VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                        (order_number, logical_key, refund_no, order.get("transaction_id"), total, fee, order["status"]))
                    if not isinstance(reason, str) or len(reason) > 512:
                        raise HTTPException(422, '退款原因最多512字符')
                    cur.execute('UPDATE payment_refund_intents SET reason=%s WHERE out_refund_no=%s', (reason, refund_no))
                    cur.execute("UPDATE orders SET status='refunding',refund_no=%s,updated_at=NOW() WHERE id=%s", (refund_no, order["id"]))
                    if order_number.startswith("OFF"):
                        cur.execute("UPDATE offline_order SET status=4,refund_id=%s WHERE order_no=%s", (refund_no, order_number))
                    if application:
                        cur.execute("UPDATE refunds SET status='seller_ok',merchant_address=%s WHERE id=%s", (merchant_address, application["id"]))
                conn.commit()
        return RefundService.recover(refund_no)

    @staticmethod
    def recover(out_refund_no):
        # Claim a bounded lease. A crash leaves an unknown attempt for query-first recovery.
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM payment_refund_intents WHERE out_refund_no=%s FOR UPDATE", (out_refund_no,))
                intent = cur.fetchone()
                if not intent:
                    raise HTTPException(404, "退款意图不存在")
                if intent["state"] in ("success", "closed", "change"):
                    return RefundService.response(intent)
                cur.execute("SELECT next_attempt_at > NOW() AS busy FROM payment_refund_intents WHERE id=%s", (intent["id"],))
                if cur.fetchone()["busy"]:
                    return RefundService.response(intent)
                cur.execute("UPDATE payment_refund_intents SET state='unknown',attempts=attempts+1,next_attempt_at=DATE_ADD(NOW(),INTERVAL 30 SECOND) WHERE id=%s", (intent["id"],))
                conn.commit()
        if intent["total_fee"] == 0:
            result = {"out_refund_no": out_refund_no, "refund_status": "SUCCESS", "amount": {"refund": 0, "total": 0, "currency": "CNY"}}
        else:
            try:
                result = None
                if intent["attempts"]:
                    result = provider.query_refund(out_refund_no, sub_mchid=intent.get("sub_mchid"))
                if result is None:
                    result = provider.refund(transaction_id=intent["transaction_id"], out_refund_no=out_refund_no,
                        total_fee=intent["total_fee"], refund_fee=intent["refund_fee"], sub_mchid=intent.get("sub_mchid"),
                        notify_url=f"{settings.public_base_url}/api/wechat-pay/refund-notify")
            except Exception as exc:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        cur.execute("UPDATE payment_refund_intents SET last_error=%s WHERE id=%s AND state NOT IN ('success','closed')", (type(exc).__name__[:64], intent["id"]))
                        conn.commit()
                raise HTTPException(503, "退款结果未知，请使用原退款号查询恢复") from None
        result = dict(result)
        result.setdefault("out_refund_no", out_refund_no)
        result.setdefault("refund_status", result.get("status", "PROCESSING"))
        RefundService.apply_result(result)
        intent["state"] = result["refund_status"].lower()
        return RefundService.response(intent)

    @staticmethod
    def response(intent):
        return {"success": True, "refund_no": intent["out_refund_no"], "status": intent["state"], "message": "退款状态已持久化；受理不代表到账"}

    @staticmethod
    def apply_result(data):
        refund_no = data.get("out_refund_no")
        status = data.get("refund_status") or data.get("status")
        if status not in ("SUCCESS", "PROCESSING", "CLOSED", "REFUNDCLOSE", "ABNORMAL", "CHANGE"):
            raise ValueError("Unsupported refund state")
        # Fixed lock order: order -> refund intent -> financial assets.
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT order_number FROM payment_refund_intents WHERE out_refund_no=%s", (refund_no,))
                identity = cur.fetchone()
                if not identity:
                    raise ValueError("Unknown refund identity")
                order_no = identity["order_number"]
                cur.execute("SELECT * FROM orders WHERE order_number=%s FOR UPDATE", (order_no,))
                order = cur.fetchone()
                cur.execute("SELECT * FROM payment_refund_intents WHERE out_refund_no=%s FOR UPDATE", (refund_no,))
                intent = cur.fetchone()
                amounts = data.get("amount", {})
                if (amounts.get("refund") != intent["refund_fee"] or amounts.get("total") != intent["total_fee"]
                        or amounts.get("currency", "CNY") != "CNY"):
                    raise ValueError("Refund amount mismatch")
                if data.get("transaction_id") and data["transaction_id"] != intent["transaction_id"]:
                    raise ValueError("Refund transaction mismatch")
                if data.get('sub_mchid') != intent.get('sub_mchid'):
                    raise ValueError('Refund submerchant mismatch')
                if intent["state"] == "success":
                    conn.commit()
                    return
                state = {"REFUNDCLOSE": "closed", "CLOSED": "closed", "ABNORMAL": "change", "CHANGE": "change"}.get(status, status.lower())
                if intent['state'] == 'closed':
                    if state != 'closed':
                        raise ValueError('Closed refund cannot transition')
                    conn.commit()
                    return
                if state == "success":
                    reverse_split_on_refund(order_no, external_conn=conn, event_key=refund_no,
                        refund_amount=Decimal(intent["refund_fee"]) / 100)
                    cur.execute("SELECT refund_fee FROM payment_refund_intents WHERE order_number=%s AND state='success' FOR UPDATE", (order_no,))
                    refunded_total = sum(int(row['refund_fee']) for row in cur.fetchall()) + intent['refund_fee']
                    fully_refunded = refunded_total == intent['total_fee']
                    cur.execute('SELECT * FROM payment_merchant_transfers WHERE order_number=%s FOR UPDATE', (order_no,))
                    transfer = cur.fetchone()
                    if transfer and transfer['attempts'] == 0:
                        original_payout = int(transfer.get('original_amount') or transfer['amount'])
                        remaining = 0 if fully_refunded else int((Decimal(original_payout) * Decimal(intent['total_fee'] - refunded_total) / Decimal(intent['total_fee'])).quantize(Decimal('1')))
                        cur.execute("UPDATE payment_merchant_transfers SET amount=%s,state=%s,next_attempt_at=NULL WHERE order_number=%s", (remaining, 'prepared' if remaining else 'closed', order_no))
                    cur.execute("UPDATE orders SET status=%s,updated_at=NOW() WHERE id=%s", ('refunded' if fully_refunded else intent['previous_status'], order['id']))
                    if fully_refunded:
                        FinanceService.revoke_order_discounts(order_no, external_cur=cur)
                    cur.execute("UPDATE refunds SET status='refund_success' WHERE order_number=%s AND status='seller_ok'", (order_no,))
                    if order_no.startswith("OFF"):
                        cur.execute("UPDATE offline_order SET status=%s,refund_time=NOW() WHERE order_no=%s", (3 if fully_refunded else 2, order_no))
                elif state == "closed":
                    cur.execute("UPDATE orders SET status=%s,updated_at=NOW() WHERE id=%s AND status='refunding'", (intent["previous_status"], order["id"]))
                    cur.execute("UPDATE payment_merchant_transfers SET state='prepared',next_attempt_at=NULL WHERE order_number=%s AND state='held' AND attempts=0", (order_no,))
                    if order_no.startswith("OFF"):
                        cur.execute("UPDATE offline_order SET status=2 WHERE order_no=%s AND status=4", (order_no,))
                cur.execute("UPDATE payment_refund_intents SET state=%s,provider_refund_id=%s,last_error=NULL,next_attempt_at=DATE_ADD(NOW(),INTERVAL 30 SECOND) WHERE id=%s", (state, data.get("refund_id"), intent["id"]))
                conn.commit()
