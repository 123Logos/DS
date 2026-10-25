"""Real issuer transactions: failed commit and committed-but-lost response recovery."""
from contextlib import contextmanager
from decimal import Decimal
import uuid
import pytest


@pytest.mark.parametrize('after_commit', [False, True])
def test_coupon_http_fault_replay_and_pool_cleanup(db, http, users, token, monkeypatch, evidence, after_commit):
    from core.config import settings
    from core.database import get_conn
    from services import finance_service
    monkeypatch.setattr(settings, 'ADMIN_USER_IDS', str(users[0]))
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET true_total_points=1 WHERE id=%s', (users[1],))
        conn.commit()
    key = uuid.uuid4().hex
    headers = {'Authorization': 'Bearer ' + token(users[0]), 'Idempotency-Key': key}
    params = {'user_id': users[1], 'amount': 1}
    original = finance_service.FinanceService.distribute_n_one_yuan_coupons
    original_conn = finance_service.get_conn
    if after_commit:
        def lost_response(self, *args, **kwargs):
            original(self, *args, **kwargs)
            raise RuntimeError('SYNTHETIC_RESPONSE_LOST_AFTER_COMMIT')
        monkeypatch.setattr(finance_service.FinanceService, 'distribute_n_one_yuan_coupons', lost_response)
    else:
        class FailCommit:
            def __init__(self, conn):
                self.conn = conn
            def __getattr__(self, name):
                return getattr(self.conn, name)
            def commit(self):
                raise RuntimeError('SYNTHETIC_PRECOMMIT_FAILURE')
        @contextmanager
        def failing():
            with get_conn() as conn:
                yield FailCommit(conn)
        monkeypatch.setattr(finance_service, 'get_conn', failing)
    response = http.post('/api/coupons/distribute', params=params, headers=headers)
    assert response.status_code >= 500
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT true_total_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['true_total_points'] == (0 if after_commit else 1)
            cur.execute('SELECT COUNT(*) n FROM coupons WHERE user_id=%s', (users[1],))
            assert cur.fetchone()['n'] == int(after_commit)
    monkeypatch.setattr(finance_service, 'get_conn', original_conn)
    monkeypatch.setattr(finance_service.FinanceService, 'distribute_n_one_yuan_coupons', original)
    responses = [http.post('/api/coupons/distribute', params=params, headers=headers) for _ in range(2)]
    assert all(r.status_code == 200 for r in responses)
    assert responses[0].json()['data']['coupon_ids'] == responses[1].json()['data']['coupon_ids']
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT true_total_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['true_total_points'] == 0
            cur.execute('SELECT COUNT(*) n,SUM(change_amount) delta FROM account_flow WHERE related_user=%s AND account_type=%s', (users[1], 'true_total_points'))
            assert cur.fetchone() == {'n': 1, 'delta': Decimal('-1')}
            cur.execute('SELECT COUNT(*) n FROM coupons WHERE user_id=%s', (users[1],))
            assert cur.fetchone()['n'] == 1
    # Reborrow from the actual application pool after a deliberately uncommitted write.
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET true_total_points=99 WHERE id=%s', (users[1],))
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT true_total_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['true_total_points'] == 0
    evidence({'after_commit_response_lost': after_commit, 'initial_http': response.status_code,
        'replay_coupon_ids': responses[0].json()['data']['coupon_ids'],
        'final_points': 0, 'coupons': 1, 'debit_ledger_count': 1, 'pooled_uncommitted_write': 'rolled_back'})
