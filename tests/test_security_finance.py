"""Run only against the guarded isolated MySQL database; no database substitutes."""
import os
from contextlib import contextmanager
from decimal import Decimal
import uuid

import pytest


@pytest.fixture
def finance_db(monkeypatch):
    from scripts.security_isolation.safety import guard
    guard()
    import pymysql
    from core.config import get_db_config
    from services import finance_service
    @contextmanager
    def connect():
        conn = pymysql.connect(**get_db_config(), cursorclass=pymysql.cursors.DictCursor)
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    monkeypatch.setattr(finance_service, 'get_conn', connect)
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO users(name,true_total_points) VALUES(%s,3)', ('finance_' + uuid.uuid4().hex,))
            uid = cur.lastrowid
        conn.commit()
    yield connect, uid
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute('DELETE FROM finance_requests WHERE actor_id=%s', (uid,))
            cur.execute('DELETE FROM account_flow WHERE related_user=%s', (uid,))
            cur.execute('DELETE FROM coupons WHERE user_id=%s', (uid,))
            cur.execute('DELETE FROM users WHERE id=%s', (uid,))
        conn.commit()


def test_durable_issue_replay_and_conflict(finance_db):
    from fastapi import HTTPException
    from services.finance_service import FinanceService
    connect, uid = finance_db
    service = FinanceService()
    key = uuid.uuid4().hex
    original = service.distribute_n_one_yuan_coupons(uid, 2, actor_id=uid, request_key=key)
    assert service.distribute_n_one_yuan_coupons(uid, 2, actor_id=uid, request_key=key) == original
    with pytest.raises(HTTPException) as error:
        service.distribute_n_one_yuan_coupons(uid, 1, actor_id=uid, request_key=key)
    assert error.value.status_code == 409
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT true_total_points FROM users WHERE id=%s', (uid,))
            assert cur.fetchone()['true_total_points'] == Decimal('1')
            cur.execute('SELECT COUNT(*) AS n FROM coupons WHERE user_id=%s', (uid,))
            assert cur.fetchone()['n'] == 2
            cur.execute("SELECT SUM(change_amount) AS n FROM account_flow WHERE related_user=%s AND account_type='true_total_points'", (uid,))
            assert cur.fetchone()['n'] == Decimal('-2')


def test_failed_multi_coupon_request_rolls_back_every_row(finance_db):
    from core.exceptions import FinanceException
    from services.finance_service import FinanceService
    connect, uid = finance_db
    with pytest.raises(FinanceException):
        FinanceService().distribute_n_one_yuan_coupons(uid, 4, actor_id=uid, request_key=uuid.uuid4().hex)
    with connect() as conn:
        with conn.cursor() as cur:
            for table, column in [('coupons', 'user_id'), ('account_flow', 'related_user'), ('finance_requests', 'actor_id')]:
                cur.execute(f'SELECT COUNT(*) AS n FROM {table} WHERE {column}=%s', (uid,))
                assert cur.fetchone()['n'] == 0
            cur.execute('SELECT true_total_points FROM users WHERE id=%s', (uid,))
            assert cur.fetchone()['true_total_points'] == Decimal('3')


def test_event_marker_rolls_back_with_assets(finance_db):
    from services.finance.durability import begin_event, finish_event
    connect, uid = finance_db
    key = uuid.uuid4().hex
    with pytest.raises(RuntimeError):
        with connect() as conn:
            with conn.cursor() as cur:
                assert not begin_event(cur, 'settlement', key, key, {'id': uid})
                cur.execute('UPDATE users SET true_total_points=0 WHERE id=%s', (uid,))
                finish_event(cur, 'settlement', key)
                raise RuntimeError('synthetic precommit fault')
    with connect() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) AS n FROM finance_events WHERE event_key=%s', (key,))
            assert cur.fetchone()['n'] == 0
            cur.execute('SELECT true_total_points FROM users WHERE id=%s', (uid,))
            assert cur.fetchone()['true_total_points'] == Decimal('3')


def test_partial_refund_replay_and_outer_rollback(finance_db):
    from services.finance_service import reverse_split_on_refund
    connect, uid = finance_db
    number = 'FIN' + uuid.uuid4().hex
    other = number + '1'
    first, second = uuid.uuid4().hex, uuid.uuid4().hex
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO orders(order_number,user_id,merchant_id,total_amount,status) VALUES(%s,%s,%s,2,'refunding')", (number, uid, uid))
                cur.execute("INSERT INTO finance_accounts(account_type,account_name,balance) VALUES('maintain_pool','maintain_pool',0) ON DUPLICATE KEY UPDATE balance=balance", ())
                cur.execute("INSERT INTO account_flow(account_type,change_amount,balance_after,flow_type,remark) VALUES('maintain_pool',2,2,'income',%s),('maintain_pool',99,101,'income',%s)", (f'订单分账: {number}', f'订单分账: {other}'))
                cur.execute("UPDATE finance_accounts SET balance=balance+101 WHERE account_type='maintain_pool'")
                cur.execute("SELECT balance FROM finance_accounts WHERE account_type='maintain_pool'")
                before = cur.fetchone()['balance']
            conn.commit()
        with connect() as conn:
            reverse_split_on_refund(number, external_conn=conn, event_key=first, refund_amount=Decimal('1'))
            conn.commit()
        with connect() as conn:
            reverse_split_on_refund(number, external_conn=conn, event_key=first, refund_amount=Decimal('1.00'))
            conn.commit()
        with pytest.raises(RuntimeError):
            with connect() as conn:
                reverse_split_on_refund(number, external_conn=conn, event_key=second, refund_amount=Decimal('1'))
                raise RuntimeError('synthetic finalization failure')
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT balance FROM finance_accounts WHERE account_type='maintain_pool'")
                assert cur.fetchone()['balance'] == before - Decimal('1')
                cur.execute("SELECT COUNT(*) AS n FROM finance_events WHERE event_key=%s", (second,))
                assert cur.fetchone()['n'] == 0
            reverse_split_on_refund(number, external_conn=conn, event_key=second, refund_amount=Decimal('1'))
            conn.commit()
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT balance FROM finance_accounts WHERE account_type='maintain_pool'")
                assert cur.fetchone()['balance'] == before - Decimal('2')
    finally:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COALESCE(SUM(change_amount),0) AS delta FROM account_flow WHERE remark IN (%s,%s,%s)", (f'订单分账: {number}', f'订单分账: {other}', f'退款回冲: {number}'))
                delta = cur.fetchone()['delta']
                cur.execute("UPDATE finance_accounts SET balance=balance-%s WHERE account_type='maintain_pool'", (delta,))
                cur.execute('DELETE FROM finance_events WHERE order_number=%s', (number,))
                cur.execute('DELETE FROM account_flow WHERE remark IN (%s,%s,%s)', (f'订单分账: {number}', f'订单分账: {other}', f'退款回冲: {number}'))
                cur.execute('DELETE FROM orders WHERE order_number=%s', (number,))
            conn.commit()


def test_only_exact_status_route_remains_public():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api.finance.routes import router
    app = FastAPI()
    app.include_router(router)
    with TestClient(app) as client:
        response = client.get('/')
        assert response.status_code == 200
        assert response.json() == {'message': '财务管理系统API运行中', 'version': '3.2.0'}
        assert client.get('/api/reports/finance').status_code in (401, 403)
        assert client.get('/api/subsidy/points-value').status_code in (401, 403)


def test_personal_weekly_monthly_aggregates_exclude_other_user(finance_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from api.finance.routes import router
    from core.auth import create_access_token
    connect, uid = finance_db
    other = None
    try:
        with connect() as conn:
            with conn.cursor() as cur:
                cur.execute('INSERT INTO users(name,true_total_points) VALUES(%s,0)', ('other_' + uuid.uuid4().hex,))
                other = cur.lastrowid
                for user_id, subsidy, points, member, merchant in [(uid, 2, 3, 5, 7), (other, 97, 101, 103, 107)]:
                    cur.execute("INSERT INTO weekly_subsidy_records(user_id,week_start,subsidy_amount,points_before,points_deducted,remark) VALUES(%s,'2026-01-05',%s,200,%s,'synthetic scoped subsidy')", (user_id, subsidy, points))
                    for kind, value in [('member', member), ('merchant', merchant)]:
                        cur.execute("INSERT INTO points_log(user_id,change_amount,balance_after,type,reason,created_at) VALUES(%s,%s,%s,%s,'synthetic scoped income','2026-01-05 12:00:00')", (user_id, value, value, kind))
            conn.commit()
        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)
        headers = {'Authorization': 'Bearer ' + create_access_token(uid, token_type='jwt')}
        for period in ('weekly', 'monthly'):
            params = {'year': 2026, 'week' if period == 'weekly' else 'month': 1}
            response = client.get(f'/api/reports/subsidy/{period}', params=params, headers=headers)
            assert response.status_code == 200
            result = response.json()['data']
            assert result['summary']['total_users'] == 1
            assert result['summary']['total_subsidy_amount'] == 2
            assert result['summary']['total_points_deducted'] == 3
            if period == 'weekly':
                assert result['summary']['company_points_balance'] is None
            for kind, expected in [('member', 5), ('merchant', 7)]:
                response = client.get(f'/api/reports/points/{kind}/{period}', params=params, headers=headers)
                assert response.status_code == 200
                result = response.json()['data']
                assert result['summary']['total_users'] == 1
                assert result['summary']['total_income'] == expected
                assert result['summary']['total_expense'] == 0
                assert all(row['user_id'] == uid for row in result['records'])
    finally:
        with connect() as conn:
            with conn.cursor() as cur:
                for user_id in (uid, other):
                    if user_id is not None:
                        cur.execute('DELETE FROM weekly_subsidy_records WHERE user_id=%s', (user_id,))
                        cur.execute('DELETE FROM points_log WHERE user_id=%s', (user_id,))
                if other is not None:
                    cur.execute('DELETE FROM sessions WHERE user_id=%s', (uid,))
                    cur.execute('DELETE FROM users WHERE id=%s', (other,))
            conn.commit()
