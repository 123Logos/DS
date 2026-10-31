"""CONTROLLED_PROVIDER_BOUNDARY: real HTTP, cryptography and MySQL; no money."""
import base64
import json
import time
import uuid
from contextlib import contextmanager
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@pytest.fixture
def paid_order(db, users):
    number = 'ISO' + uuid.uuid4().hex
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET member_points=10 WHERE id=%s', (users[1],))
            cur.execute("INSERT INTO orders(order_number,user_id,merchant_id,total_amount,pending_points,status,transaction_id) VALUES(%s,%s,%s,1,2,'pending_ship',%s)",
                (number, users[1], users[2], 'TX' + uuid.uuid4().hex))
            cur.execute("UPDATE finance_accounts SET balance=balance+1 WHERE account_type='maintain_pool'")
            cur.execute("INSERT INTO account_flow(account_type,related_user,change_amount,balance_after,flow_type,remark) SELECT 'maintain_pool',%s,1,balance,'income',%s FROM finance_accounts WHERE account_type='maintain_pool'", (users[1], '订单分账: ' + number))
        conn.commit()
    return number


@pytest.fixture
def signed_callback(monkeypatch):
    from api.wechat_pay import routes
    from core.config import settings
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    aes = b'I' * 32
    monkeypatch.setattr(routes.pay_client, 'wechat_public_key', key.public_key())
    monkeypatch.setattr(routes.pay_client, 'apiv3_key', aes)
    monkeypatch.setattr(settings, 'WECHAT_PAY_PUB_KEY_ID', 'ISOLATED_RSA_KEY')
    monkeypatch.setattr(settings, 'WECHAT_PAY_MCH_ID', 'ISOLATED_MERCHANT')
    def encode(data, event='REFUND.SUCCESS'):
        nonce = 'isolation123'
        resource = {'nonce': nonce, 'associated_data': 'isolation',
            'ciphertext': base64.b64encode(AESGCM(aes).encrypt(nonce.encode(),
                json.dumps({**data, 'mchid': 'ISOLATED_MERCHANT'}).encode(), b'isolation')).decode()}
        body = json.dumps({'id': uuid.uuid4().hex, 'event_type': event, 'resource': resource})
        timestamp = str(int(time.time()))
        signature = key.sign(f'{timestamp}\nrequestnonce\n{body}\n'.encode(), padding.PKCS1v15(), hashes.SHA256())
        return body, {'Wechatpay-Signature': base64.b64encode(signature).decode(),
            'Wechatpay-Timestamp': timestamp, 'Wechatpay-Nonce': 'requestnonce', 'Wechatpay-Serial': 'ISOLATED_RSA_KEY'}
    return encode


def test_external_accepted_commit_failure_recovery(db, http, users, token, paid_order, monkeypatch, evidence, signed_callback):
    from services import refund_service
    from core.database import get_conn
    accepted = []
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT balance FROM finance_accounts WHERE account_type='maintain_pool'")
            pool_before = cur.fetchone()['balance']
    results = {}
    class Provider:
        def refund(self, **kwargs):
            number = kwargs['out_refund_no']
            accepted.append(number)
            result = {'out_refund_no': number, 'refund_status': 'SUCCESS', 'refund_id': 'ISOLATED_REFUND',
                'amount': {'refund': 100, 'total': 100, 'currency': 'CNY'}}
            results[number] = result
            return result
        def query_refund(self, number, **kwargs):
            return results[number]
    monkeypatch.setattr(refund_service, 'provider', Provider())
    # Fail exactly the transaction after provider acceptance, not the durable intent/lease commits.
    class FailingCommit:
        def __init__(self, conn):
            self.conn = conn
        def __getattr__(self, name):
            return getattr(self.conn, name)
        def commit(self):
            if accepted:
                raise RuntimeError('ISOLATED_COMMIT_FAILURE')
            self.conn.commit()
    @contextmanager
    def failing_conn():
        with get_conn() as conn:
            yield FailingCommit(conn)
    monkeypatch.setattr(refund_service, 'get_conn', failing_conn)
    response = http.post('/wechat-pay/refund', json={'order_number': paid_order, 'refund_fee': 100},
        headers={'Authorization': 'Bearer ' + token(users[1])})
    assert response.status_code >= 500
    assert len(accepted) == 1
    number = accepted[0]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT state FROM payment_refund_intents WHERE out_refund_no=%s', (number,))
            assert cur.fetchone()['state'] == 'unknown'
            cur.execute('SELECT status FROM orders WHERE order_number=%s', (paid_order,))
            assert cur.fetchone()['status'] == 'refunding'
            cur.execute('SELECT member_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['member_points'] == 10
            cur.execute("SELECT balance FROM finance_accounts WHERE account_type='maintain_pool'")
            assert cur.fetchone()['balance'] == pool_before
            cur.execute('SELECT COUNT(*) n FROM finance_events WHERE order_number=%s', (paid_order,))
            assert cur.fetchone()['n'] == 0
            cur.execute('UPDATE payment_refund_intents SET next_attempt_at=NOW() WHERE out_refund_no=%s', (number,))
        conn.commit()
    monkeypatch.setattr(refund_service, 'get_conn', get_conn)
    refund_service.RefundService.recover(number)
    for _ in range(2):
        body, headers = signed_callback(results[number])
        replay = http.post('/api/wechat-pay/refund-notify', content=body, headers=headers)
        assert replay.status_code == 204
    assert accepted == [number]
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM orders WHERE order_number=%s', (paid_order,))
            assert cur.fetchone()['status'] == 'refunded'
            cur.execute('SELECT state,attempts FROM payment_refund_intents WHERE out_refund_no=%s', (number,))
            final = cur.fetchone()
            assert final['state'] == 'success'
            cur.execute('SELECT member_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['member_points'] == 12
            cur.execute("SELECT balance FROM finance_accounts WHERE account_type='maintain_pool'")
            assert cur.fetchone()['balance'] == pool_before - 1
            cur.execute('SELECT COUNT(*) n,SUM(change_amount) delta FROM account_flow WHERE account_type=%s AND remark=%s', ('maintain_pool', '退款回冲: ' + paid_order))
            assert cur.fetchone() == {'n': 1, 'delta': -1}
            cur.execute("SELECT COUNT(*) n,SUM(change_amount) delta FROM points_log WHERE user_id=%s AND reason=%s", (users[1], '订单退款退回积分: ' + paid_order))
            assert cur.fetchone() == {'n': 1, 'delta': 2}
    evidence({'provider_evidence': 'CONTROLLED_BOUNDARY_ONLY', 'external_calls': len(accepted),
        'local_commit_failure': response.status_code, 'replay': 'twice', 'final': final})


def test_unsigned_callback_cannot_mutate(http, paid_order):
    response = http.post('/api/wechat-pay/notify', json={'out_trade_no': paid_order, 'trade_state': 'SUCCESS'})
    assert response.status_code == 401
