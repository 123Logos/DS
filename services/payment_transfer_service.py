"""Post-commit recovery for the existing offline merchant wallet transfer policy."""
import json
from urllib.parse import quote
from core.database import get_conn
from core.config import settings
from core.wx_pay_client import wxpay_client

provider = wxpay_client


def recover_transfer(order_number):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM orders WHERE order_number=%s FOR UPDATE', (order_number,))
            order = cur.fetchone()
            if not order:
                raise ValueError('Unknown payout order')
            cur.execute('SELECT *,next_attempt_at>NOW() AS busy FROM payment_merchant_transfers WHERE order_number=%s FOR UPDATE', (order_number,))
            row = cur.fetchone()
            if not row or row['state'] in ('closed', 'held') or (row['state'] == 'finished' and row.get('notification_sent')) or row['busy']:
                return
            if order['status'] in ('refunding', 'refunded') and row['attempts'] == 0:
                cur.execute("UPDATE payment_merchant_transfers SET state='closed' WHERE order_number=%s", (order_number,))
                conn.commit()
                return
            if not row.get('beneficiary_openid'):
                raise ValueError('Merchant beneficiary missing; reconcile before transfer')
            cur.execute("UPDATE payment_merchant_transfers SET state=IF(state='finished','finished','unknown'),attempts=attempts+1,next_attempt_at=DATE_ADD(NOW(),INTERVAL 60 SECOND) WHERE order_number=%s", (order_number,))
            conn.commit()
    if row['state'] == 'finished' and not row.get('notification_sent'):
        from services.notify_service import _notify_template
        from decimal import Decimal
        import asyncio
        asyncio.run(_notify_template(row['beneficiary_openid'], order_number, Decimal(row['amount']) / 100))
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE payment_merchant_transfers SET notification_sent=1 WHERE order_number=%s', (order_number,))
                conn.commit()
        return
    path = '/v3/transfer/batches/out-batch-no/' + quote(row['out_batch_no'], safe='') + '?need_query_detail=false'
    result = None
    if row['attempts']:
        response = provider.session.get(provider.BASE_URL + path,
            headers={'Authorization': provider._build_auth_header('GET', path), 'Accept': 'application/json'}, timeout=15)
        if response.status_code != 404:
            response.raise_for_status()
            result = response.json()
        elif response.json().get('code') != 'NOT_FOUND':
            response.raise_for_status()
    if result is None:
        path = '/v3/transfer/batches'
        payload = {'appid': settings.WECHAT_APP_ID, 'out_batch_no': row['out_batch_no'],
            'batch_name': '线下收银到账', 'batch_remark': '线下订单收款', 'total_amount': row['amount'], 'total_num': 1,
            'transfer_detail_list': [{'out_detail_no': row['out_batch_no'], 'transfer_amount': row['amount'],
                'transfer_remark': '线下订单收款', 'openid': row['beneficiary_openid']}]}
        body = json.dumps(payload, ensure_ascii=False)
        response = provider.session.post(provider.BASE_URL + path, data=body.encode(),
            headers={'Authorization': provider._build_auth_header('POST', path, body), 'Content-Type': 'application/json', 'Accept': 'application/json'}, timeout=15)
        response.raise_for_status()
        result = response.json()
    batch = result.get('transfer_batch', result)
    if batch.get('out_batch_no') and batch['out_batch_no'] != row['out_batch_no']:
        raise ValueError('Transfer identity mismatch')
    state = 'processing'
    if batch.get('batch_status') == 'FINISHED':
        state = 'finished' if batch.get('success_amount') == row['amount'] and batch.get('fail_num', 0) == 0 else 'closed'
    elif batch.get('batch_status') == 'CLOSED':
        state = 'closed'
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE payment_merchant_transfers SET state=%s WHERE order_number=%s', (state, order_number))
            conn.commit()
