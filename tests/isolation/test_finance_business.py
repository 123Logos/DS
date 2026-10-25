import threading
import uuid
from contextlib import contextmanager
import pytest


@pytest.mark.parametrize('same_key', [False, True])
def test_coupon_http_balance_competition(db, http, users, token, monkeypatch, race, evidence, same_key):
    from core.config import settings
    from services import finance_service
    from fastapi.testclient import TestClient
    from main import app
    monkeypatch.setattr(settings, 'ADMIN_USER_IDS', str(users[0]))
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET true_total_points=1 WHERE id=%s', (users[1],))
        conn.commit()
    headers = {'Authorization': 'Bearer ' + token(users[0])}
    key = uuid.uuid4().hex
    original = finance_service.get_conn
    barrier = threading.Barrier(2)
    identities = []
    @contextmanager
    def coordinated():
        with original() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT CONNECTION_ID() id')
                identities.append(cur.fetchone()['id'])
            if len(identities) <= 2:
                barrier.wait(timeout=15)
            yield conn
    monkeypatch.setattr(finance_service, 'get_conn', coordinated)
    def issue(request_key):
        # Separate portals: production async route performs synchronous database I/O.
        with TestClient(app, raise_server_exceptions=False) as client:
            return client.post('/api/coupons/distribute', params={'user_id': users[1], 'amount': 1},
                headers={**headers, 'Idempotency-Key': request_key})
    responses = race(lambda: issue(key), lambda: issue(key if same_key else uuid.uuid4().hex))
    monkeypatch.setattr(finance_service, 'get_conn', original)
    assert len(set(identities[:2])) == 2
    assert sorted(r.status_code for r in responses) == ([200, 200] if same_key else [200, 400])
    if same_key:
        assert responses[0].json()['data']['coupon_ids'] == responses[1].json()['data']['coupon_ids']
        changed = http.post('/api/coupons/distribute', params={'user_id': users[1], 'amount': 2},
            headers={**headers, 'Idempotency-Key': key})
        assert changed.status_code == 409
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT true_total_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['true_total_points'] == 0
            cur.execute('SELECT COUNT(*) n FROM coupons WHERE user_id=%s', (users[1],))
            assert cur.fetchone()['n'] == 1
    evidence({'connections': identities, 'statuses': [r.status_code for r in responses],
        'same_key': same_key, 'invariants': {'remaining_points': 0, 'coupons': 1}})


def test_coupon_admin_key_cannot_authorize(db, http, users, token, evidence):
    for headers in ({}, {'Authorization': 'Bearer ' + token(users[1])}):
        response = http.post('/api/coupons/distribute',
            params={'user_id': users[1], 'amount': 1, 'admin_key': 'admin2025', 'key': 'admin2025'},
            headers={**headers, 'Idempotency-Key': uuid.uuid4().hex})
        assert response.status_code in (401, 403)
    evidence({'legacy_shared_key': 'denied'})
