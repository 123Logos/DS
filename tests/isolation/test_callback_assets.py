"""Actual online settlement/refund assets; synthetic cryptographic provider identity."""
from contextlib import contextmanager
from decimal import Decimal
import uuid
import pytest
from test_payment_business import signed_callback


@pytest.mark.parametrize('fault', ['settlement', 'commit'])
def test_signed_payment_failure_replay_and_refund_assets(db, http, users, monkeypatch, signed_callback, evidence, fault):
    from api.wechat_pay import routes
    from services.finance_service import FinanceService
    from core.database import get_conn
    import logging
    from core.config import LOG_FILE
    root = logging.getLogger()
    monkeypatch.setattr(root, 'level', logging.DEBUG)
    for handler in root.handlers:
        monkeypatch.setattr(handler, 'level', logging.DEBUG)
        handler.flush()
    log_offset = LOG_FILE.stat().st_size if LOG_FILE.exists() else 0
    canaries = ('SYNTHETIC_CALLBACK_BODY_SECRET_73841',
        'SYNTHETIC_CALLBACK_BEARER_84952', 'SYNTHETIC_CALLBACK_COOKIE_95063')
    number = 'ASSET' + uuid.uuid4().hex
    transaction = 'TX' + uuid.uuid4().hex
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET member_points=0 WHERE id=%s', (users[1],))
            cur.execute("INSERT INTO products(name,user_id,status) VALUES('Synthetic settlement product',%s,1)", (users[2],))
            product = cur.lastrowid
            cur.execute("INSERT INTO orders(order_number,user_id,merchant_id,total_amount,original_amount,status) VALUES(%s,%s,%s,10,10,'pending_pay')", (number, users[1], users[2]))
            oid = cur.lastrowid
            cur.execute('INSERT INTO order_items(order_id,product_id,quantity,unit_price,total_price) VALUES(%s,%s,1,10,10)', (oid, product))
            cur.execute('SELECT account_type,balance FROM finance_accounts')
            before = {row['account_type']: row['balance'] for row in cur.fetchall()}
        conn.commit()
    payload = {'out_trade_no': number, 'transaction_id': transaction, 'trade_state': 'SUCCESS',
        'amount': {'total': 1000, 'currency': 'CNY'}, 'sensitive_provider_payload': canaries[0]}
    body, headers = signed_callback(payload, 'TRANSACTION.SUCCESS')
    headers.update({'Authorization': 'Bearer ' + canaries[1], 'Cookie': 'session=' + canaries[2]})
    original_settle = FinanceService.settle_order
    original_conn = routes.get_conn
    if fault == 'settlement':
        def fail_after_settle(self, *args, **kwargs):
            original_settle(self, *args, **kwargs)
            raise RuntimeError('ISOLATED_POST_SETTLEMENT_FAULT')
        monkeypatch.setattr(FinanceService, 'settle_order', fail_after_settle)
    else:
        class FailCommit:
            def __init__(self, conn):
                self.conn = conn
            def __getattr__(self, name):
                return getattr(self.conn, name)
            def commit(self):
                raise RuntimeError('ISOLATED_CALLBACK_COMMIT_FAULT')
        @contextmanager
        def failing():
            with get_conn() as conn:
                yield FailCommit(conn)
        monkeypatch.setattr(routes, 'get_conn', failing)
    failed = http.post('/api/wechat-pay/notify', content=body, headers=headers)
    assert failed.status_code == 503
    for handler in root.handlers:
        handler.flush()
    with LOG_FILE.open('rb') as stream:
        stream.seek(log_offset)
        callback_logs = stream.read().decode('utf-8', errors='replace')
    assert 'payment_notification_storage_failure' in callback_logs
    assert all(canary not in callback_logs for canary in canaries)
    assert body not in callback_logs
    assert headers['Wechatpay-Signature'] not in callback_logs
    assert headers['Authorization'] not in callback_logs
    evidence({'callback_log_level': 'DEBUG', 'storage_failure_event_retained': True,
        'payload_and_header_canaries_absent': True})
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT member_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['member_points'] == 0
            cur.execute('SELECT status FROM orders WHERE id=%s', (oid,))
            assert cur.fetchone()['status'] == 'pending_pay'
            for table, column in [('points_log', 'related_order'), ('payment_events', 'order_number'), ('finance_events', 'order_number')]:
                cur.execute(f'SELECT COUNT(*) n FROM {table} WHERE {column}=%s', (oid if table == 'points_log' else number,))
                assert cur.fetchone()['n'] == 0
            cur.execute('SELECT account_type,balance FROM finance_accounts')
            assert {r['account_type']: r['balance'] for r in cur.fetchall()} == before
    monkeypatch.setattr(FinanceService, 'settle_order', original_settle)
    monkeypatch.setattr(routes, 'get_conn', original_conn)
    for _ in range(2):
        body, headers = signed_callback(payload, 'TRANSACTION.SUCCESS')
        assert http.post('/api/wechat-pay/notify', content=body, headers=headers).status_code == 204
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT member_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['member_points'] == Decimal('10')
            cur.execute('SELECT user_id,type,COUNT(*) n,SUM(change_amount) delta FROM points_log WHERE related_order=%s GROUP BY user_id,type', (oid,))
            ledger = {(row['user_id'], row['type']): (row['n'], row['delta']) for row in cur.fetchall()}
            assert ledger == {(users[1], 'member'): (1, Decimal('10')), (0, 'company'): (1, Decimal('2'))}
            cur.execute('SELECT COUNT(*) n FROM payment_events WHERE order_number=%s', (number,))
            assert cur.fetchone()['n'] == 1
            cur.execute("SELECT balance FROM finance_accounts WHERE account_type='company_points'")
            assert cur.fetchone()['balance'] == before['company_points'] + Decimal('2')
            refund_no = 'RF' + uuid.uuid4().hex
            cur.execute("INSERT INTO payment_refund_intents(order_number,logical_key,out_refund_no,transaction_id,total_fee,refund_fee,previous_status,state) VALUES(%s,%s,%s,%s,1000,1000,'pending_ship','unknown')", (number, 'direct:' + number, refund_no, transaction))
            cur.execute("UPDATE orders SET status='refunding' WHERE id=%s", (oid,))
        conn.commit()
    refund = {'out_refund_no': refund_no, 'transaction_id': transaction, 'refund_status': 'SUCCESS',
        'amount': {'total': 1000, 'refund': 1000, 'currency': 'CNY'}}
    for _ in range(2):
        body, headers = signed_callback(refund)
        assert http.post('/api/wechat-pay/refund-notify', content=body, headers=headers).status_code == 204
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT member_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['member_points'] == 0
            cur.execute('SELECT status FROM orders WHERE id=%s', (oid,))
            assert cur.fetchone()['status'] == 'refunded'
            cur.execute("SELECT event_kind,COUNT(*) n FROM finance_events WHERE order_number=%s GROUP BY event_kind", (number,))
            events = {row['event_kind']: row['n'] for row in cur.fetchall()}
            assert events == {'settlement': 1, 'refund_split': 1, 'discount_refund': 1}
            cur.execute('SELECT account_type,balance FROM finance_accounts')
            after = {row['account_type']: row['balance'] for row in cur.fetchall()}
            assert after == before
    evidence({'fault': fault, 'failure_http': failed.status_code, 'points': '0->10->0',
        'finance_events': events, 'pool_balances_before': before, 'pool_balances_after': after,
        'provider_evidence': 'SYNTHETIC_RSA_AES_NO_EXTERNAL_PROVIDER'})
