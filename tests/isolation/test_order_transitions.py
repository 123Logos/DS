"""Actual HTTP and InnoDB state transitions; controlled provider, no money."""
import uuid
import pytest


def create_order(db, users, status):
    number = 'RACE' + uuid.uuid4().hex
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO orders(order_number,user_id,merchant_id,total_amount,status,transaction_id,delivery_way) VALUES(%s,%s,%s,1,%s,%s,'pickup')",
                (number, users[1], users[2], status, 'TX' + uuid.uuid4().hex))
        conn.commit()
    return number


@pytest.mark.parametrize('initial,action', [('pending_recv', 'receive'), ('pending_ship', 'ship')])
@pytest.mark.parametrize('refund_first', [True, False])
def test_refund_fulfillment_serial_orders(db, http, users, token, monkeypatch, initial, action, refund_first):
    from services import refund_service
    class Provider:
        def refund(self, **kwargs):
            return {'status': 'PROCESSING', 'amount': {'refund': kwargs['refund_fee'], 'total': kwargs['total_fee'], 'currency': 'CNY'}}
    monkeypatch.setattr(refund_service, 'provider', Provider())
    number = create_order(db, users, initial)
    def fulfillment():
        if action == 'receive':
            return http.post('/order/confirm-receive', json={'order_number': number}, headers={'Authorization': 'Bearer ' + token(users[1])})
        return http.post('/merchant/ship', json={'order_number': number, 'logistics_type': 4}, headers={'Authorization': 'Bearer ' + token(users[2])})
    def refund():
        return http.post('/wechat-pay/refund', json={'order_number': number}, headers={'Authorization': 'Bearer ' + token(users[1])})
    if refund_first:
        assert refund().status_code == 200
        result = fulfillment()
        assert result.status_code >= 400 or not result.json().get('ok')
    else:
        assert fulfillment().status_code == 200
        assert refund().status_code == 200
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM orders WHERE order_number=%s', (number,))
            assert cur.fetchone()['status'] == 'refunding'


def test_expiration_prevents_late_payment_mutation(db, users):
    import asyncio
    from api.order.order import _cancel_expire_orders_once
    from api.wechat_pay.routes import handle_transaction_success
    number = create_order(db, users, 'pending_pay')
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE orders SET expire_at=DATE_SUB(NOW(),INTERVAL 1 SECOND) WHERE order_number=%s', (number,))
        conn.commit()
    _cancel_expire_orders_once()
    with pytest.raises(ValueError):
        asyncio.run(handle_transaction_success({'out_trade_no': number, 'transaction_id': 'LATE' + uuid.uuid4().hex,
            'amount': {'total': 100, 'currency': 'CNY'}}))
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM orders WHERE order_number=%s', (number,))
            assert cur.fetchone()['status'] == 'cancelled'
            cur.execute('SELECT COUNT(*) AS n FROM payment_events WHERE order_number=%s', (number,))
            assert cur.fetchone()['n'] == 0

def test_refund_lock_blocks_receive_until_intent_commit(db, http, users, token, monkeypatch, evidence):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import contextmanager
    from services import refund_service
    from core.database import get_conn
    number = create_order(db, users, 'pending_recv')
    locked = threading.Event()
    release = threading.Event()
    receive_attempted = threading.Event()
    ids = []
    class Cursor:
        def __init__(self, cur): self.cur = cur
        def __enter__(self): return self
        def __exit__(self, *args): self.cur.close()
        def __getattr__(self, name): return getattr(self.cur, name)
        def execute(self, sql, args=None):
            if 'FROM orders WHERE order_number=%s FOR UPDATE' in sql and sql.startswith('SELECT id, user_id'):
                receive_attempted.set()
            result = self.cur.execute(sql, args)
            if sql == 'SELECT * FROM orders WHERE order_number=%s FOR UPDATE':
                locked.set()
                assert release.wait(15)
            return result
    class Connection:
        def __init__(self, conn): self.conn = conn
        def __getattr__(self, name): return getattr(self.conn, name)
        def cursor(self): return Cursor(self.conn.cursor())
    @contextmanager
    def instrumented():
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT CONNECTION_ID() AS id')
                ids.append(cur.fetchone()['id'])
            yield Connection(conn)
    class Provider:
        def refund(self, **kwargs):
            return {'status': 'PROCESSING', 'amount': {'refund': 100, 'total': 100, 'currency': 'CNY'}}
    monkeypatch.setattr(refund_service, 'get_conn', instrumented)
    from api.order import order as order_routes
    monkeypatch.setattr(order_routes, 'get_conn', instrumented)
    monkeypatch.setattr(refund_service, 'provider', Provider())
    buyer_headers = {'Authorization': 'Bearer ' + token(users[1])}
    from fastapi.testclient import TestClient
    from main import app
    # Independent portals ensure async refund lock instrumentation cannot block receipt dispatch.
    with TestClient(app, raise_server_exceptions=False) as refund_http, TestClient(app, raise_server_exceptions=False) as receive_http:
        def refund():
            return refund_http.post('/wechat-pay/refund', json={'order_number': number}, headers=buyer_headers)
        def receive():
            return receive_http.post('/order/confirm-receive', json={'order_number': number}, headers=buyer_headers)
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(refund)
            assert locked.wait(15)
            second = pool.submit(receive)
            assert receive_attempted.wait(15)
            assert len(set(ids)) >= 2
            release.set()
            assert first.result(20).status_code == 200
            result = second.result(20)
            assert result.status_code >= 400 or not result.json().get('ok')
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM orders WHERE order_number=%s', (number,))
            assert cur.fetchone()['status'] == 'refunding'
    evidence({'scenario': 'refund-lock-before-receive', 'refund_connections': ids, 'final': 'refunding'})

def test_full_refund_restores_coupon_points_once(db, http, users, token, monkeypatch, evidence):
    from decimal import Decimal
    from services import refund_service
    number = create_order(db, users, 'pending_ship')
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET member_points=10 WHERE id=%s', (users[1],))
            cur.execute("INSERT INTO coupons(user_id,coupon_type,amount,status,valid_from,valid_to,used_at) VALUES(%s,'user',1,'used',CURDATE(),DATE_ADD(CURDATE(),INTERVAL 7 DAY),NOW())", (users[1],))
            coupon = cur.lastrowid
            cur.execute('UPDATE orders SET pending_points=2,pending_coupon_ids=%s WHERE order_number=%s', ('[' + str(coupon) + ']', number))
        conn.commit()
    class Provider:
        def refund(self, **kwargs):
            return {'out_refund_no': kwargs['out_refund_no'], 'status': 'SUCCESS', 'amount': {'refund': 100, 'total': 100, 'currency': 'CNY'}}
    monkeypatch.setattr(refund_service, 'provider', Provider())
    response = http.post('/wechat-pay/refund', json={'order_number': number}, headers={'Authorization': 'Bearer ' + token(users[1])})
    assert response.status_code == 200
    refund_no = response.json()['refund_no']
    # Replay actual finalizer after terminal commit, not an isolated SQL surrogate.
    refund_service.RefundService.apply_result({'out_refund_no': refund_no, 'refund_status': 'SUCCESS', 'amount': {'refund': 100, 'total': 100, 'currency': 'CNY'}})
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM orders WHERE order_number=%s', (number,))
            assert cur.fetchone()['status'] == 'refunded'
            cur.execute('SELECT member_points FROM users WHERE id=%s', (users[1],))
            points = cur.fetchone()['member_points']
            assert points == Decimal('12')
            cur.execute('SELECT status,used_at FROM coupons WHERE id=%s', (coupon,))
            restored = cur.fetchone()
            assert restored == {'status': 'unused', 'used_at': None}
            cur.execute('SELECT COUNT(*) AS n FROM points_log WHERE user_id=%s AND reason=%s', (users[1], '订单退款退回积分: ' + number))
            assert cur.fetchone()['n'] == 1
    evidence({'scenario': 'full-refund-assets-replay', 'points_before': '10', 'points_after': str(points), 'coupon_before': 'used', 'coupon_after': restored})

def test_direct_refund_retry_survives_new_application(db, http, users, token, monkeypatch):
    from services import refund_service
    number = create_order(db, users, 'pending_ship')
    calls=[]
    class Provider:
        def refund(self, **kwargs):
            calls.append(kwargs['out_refund_no'])
            return {'status':'SUCCESS','amount':{'refund':40,'total':100,'currency':'CNY'}}
    monkeypatch.setattr(refund_service,'provider',Provider())
    headers={'Authorization':'Bearer '+token(users[1])}
    payload={'order_number':number,'refund_fee':40,'refund_request_id':'same-item'}
    first=http.post('/wechat-pay/refund',json=payload,headers=headers)
    assert first.status_code==200
    assert http.post('/refund/apply',json={'order_number':number,'refund_type':'refund_only','reason_code':'synthetic'},headers=headers).status_code==200
    replay=http.post('/wechat-pay/refund',json=payload,headers=headers)
    assert replay.status_code==200
    assert replay.json()['refund_no']==first.json()['refund_no']
    assert len(calls)==1


@pytest.mark.parametrize('attempts',[0,1])
def test_refund_coordinates_prepared_or_unknown_payout(db,http,users,token,monkeypatch,attempts):
    from services import refund_service
    number=create_order(db,users,'completed')
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('INSERT INTO payment_merchant_transfers(order_number,merchant_id,amount,out_batch_no,attempts,state) VALUES(%s,%s,80,%s,%s,%s)',(number,users[2],__import__('uuid').uuid4().hex,attempts,'unknown' if attempts else 'prepared'))
        conn.commit()
    calls=[]
    class Provider:
        def refund(self,**kwargs):
            calls.append(kwargs)
            return {'status':'PROCESSING','amount':{'refund':100,'total':100,'currency':'CNY'}}
    monkeypatch.setattr(refund_service,'provider',Provider())
    result=http.post('/wechat-pay/refund',json={'order_number':number},headers={'Authorization':'Bearer '+token(users[1])})
    assert result.status_code==(409 if attempts else 200)
    assert len(calls)==(0 if attempts else 1)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT state FROM payment_merchant_transfers WHERE order_number=%s',(number,))
            assert cur.fetchone()['state']==('unknown' if attempts else 'held')

@pytest.mark.parametrize('terminal,expected_amount',[('SUCCESS',48),('CLOSED',80)])
def test_partial_refund_payout_terminal_reservation(db,http,users,token,monkeypatch,terminal,expected_amount):
    from services import refund_service
    number=create_order(db,users,'completed')
    batch=__import__('uuid').uuid4().hex
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO payment_merchant_transfers(order_number,merchant_id,amount,out_batch_no,state) VALUES(%s,%s,80,%s,'prepared')",(number,users[2],batch))
        conn.commit()
    class Provider:
        def refund(self,**kwargs):
            return {'status':'PROCESSING','amount':{'refund':40,'total':100,'currency':'CNY'}}
    monkeypatch.setattr(refund_service,'provider',Provider())
    response=http.post('/wechat-pay/refund',json={'order_number':number,'refund_fee':40},headers={'Authorization':'Bearer '+token(users[1])})
    assert response.status_code==200
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT state,amount FROM payment_merchant_transfers WHERE order_number=%s',(number,))
            assert cur.fetchone()=={'state':'held','amount':80}
    refund_service.RefundService.apply_result({'out_refund_no':response.json()['refund_no'],'refund_status':terminal,'amount':{'refund':40,'total':100,'currency':'CNY'}})
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT state,amount,out_batch_no,attempts FROM payment_merchant_transfers WHERE order_number=%s',(number,))
            assert cur.fetchone()=={'state':'prepared','amount':expected_amount,'out_batch_no':batch,'attempts':0}

def test_old_closed_refund_replay_does_not_release_new_refund(db,http,users,token,monkeypatch):
    from services import refund_service
    number=create_order(db,users,'completed')
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO payment_merchant_transfers(order_number,merchant_id,amount,out_batch_no,state) VALUES(%s,%s,80,%s,'prepared')",(number,users[2],__import__('uuid').uuid4().hex))
        conn.commit()
    class Provider:
        def refund(self,**kwargs):
            return {'status':'PROCESSING','amount':{'refund':40,'total':100,'currency':'CNY'}}
    monkeypatch.setattr(refund_service,'provider',Provider())
    headers={'Authorization':'Bearer '+token(users[1])}
    def request(key):
        response=http.post('/wechat-pay/refund',json={'order_number':number,'refund_fee':40,'refund_request_id':key},headers=headers)
        assert response.status_code==200
        return response.json()['refund_no']
    first=request('A')
    closed={'out_refund_no':first,'refund_status':'CLOSED','amount':{'refund':40,'total':100,'currency':'CNY'}}
    refund_service.RefundService.apply_result(closed)
    second=request('B')
    assert first!=second
    refund_service.RefundService.apply_result(closed)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status,refund_no FROM orders WHERE order_number=%s',(number,))
            assert cur.fetchone()=={'status':'refunding','refund_no':second}
            cur.execute('SELECT state,amount,attempts FROM payment_merchant_transfers WHERE order_number=%s',(number,))
            assert cur.fetchone()=={'state':'held','amount':80,'attempts':0}
    refund_service.RefundService.apply_result({'out_refund_no':second,'refund_status':'SUCCESS','amount':{'refund':40,'total':100,'currency':'CNY'}})
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM orders WHERE order_number=%s',(number,))
            assert cur.fetchone()['status']=='completed'
            cur.execute('SELECT state,amount,attempts FROM payment_merchant_transfers WHERE order_number=%s',(number,))
            assert cur.fetchone()=={'state':'prepared','amount':48,'attempts':0}

def test_refund_apply_invalid_enum_rejected_before_database(http,users,token):
    response=http.post('/refund/apply',json={'order_number':'synthetic','refund_type':'refund','reason_code':'synthetic'},headers={'Authorization':'Bearer '+token(users[1])})
    assert response.status_code==422
