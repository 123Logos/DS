"""Actual independent HTTP portals and real MySQL transition overlap."""
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import pytest
from fastapi.testclient import TestClient
from test_order_transitions import create_order


@pytest.mark.parametrize('action,status', [('receive','pending_recv'), ('ship','pending_ship')])
def test_duplicate_fulfillment_overlap(db, users, token, monkeypatch, action, status, evidence):
    from main import app
    from api.order import order, merchant
    from core.database import get_conn
    number = create_order(db, users, status)
    barrier = threading.Barrier(2)
    ids = []
    @contextmanager
    def connected():
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT CONNECTION_ID() AS id')
                ids.append(cur.fetchone()['id'])
            barrier.wait(15)
            yield conn
    # These routes have an authorization pre-read as well as the authoritative transaction.
    if action == 'receive':
        monkeypatch.setattr(order, 'get_conn', connected)
    else:
        class Cursor:
            def __init__(self,cur,conn): self.cur,self.conn=cur,conn
            def __enter__(self): return self
            def __exit__(self,*args): self.cur.close()
            def __getattr__(self,name): return getattr(self.cur,name)
            def execute(self,sql,args=None):
                if 'WHERE o.order_number=%s FOR UPDATE' in sql:
                    with self.conn.cursor() as identity:
                        identity.execute('SELECT CONNECTION_ID() AS id')
                        ids.append(identity.fetchone()['id'])
                    barrier.wait(15)
                return self.cur.execute(sql,args)
        class Connection:
            def __init__(self,conn): self.conn=conn
            def __getattr__(self,name): return getattr(self.conn,name)
            def cursor(self): return Cursor(self.conn.cursor(),self.conn)
        @contextmanager
        def shipping_connection():
            with get_conn() as conn:
                yield Connection(conn)
        monkeypatch.setattr(merchant,'get_conn',shipping_connection)
    headers = {'Authorization': 'Bearer ' + token(users[1] if action == 'receive' else users[2])}
    path = '/order/confirm-receive' if action == 'receive' else '/merchant/ship'
    body = {'order_number': number, 'logistics_type': 4}
    with TestClient(app, raise_server_exceptions=False) as a, TestClient(app, raise_server_exceptions=False) as b:
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(client.post, path, json=body, headers=headers) for client in (a,b)]
            responses = [f.result(20) for f in futures]
    assert sum(r.status_code == 200 and r.json().get('ok') is True for r in responses) == 1
    assert len(set(ids)) >= 2
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM orders WHERE order_number=%s', (number,))
            assert cur.fetchone()['status'] == ('completed' if action == 'receive' else 'pending_recv')
    evidence({'duplicate': action, 'statuses': [r.status_code for r in responses], 'connection_ids': ids})

@pytest.mark.parametrize('pay_first', [True, False])
def test_payment_expiration_true_overlap(db, users, token, monkeypatch, pay_first, evidence):
    from main import app
    from api.order import order
    from api.wechat_pay import routes
    from core.database import get_conn
    # Seed actual product-backed pending purchase via HTTP before instrumenting transaction locks.
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO products(name,user_id,status) VALUES('Expiry synthetic',%s,1)", (users[2],))
            pid = cur.lastrowid
            cur.execute('INSERT INTO product_skus(product_id,sku_code,price,stock) VALUES(%s,%s,1,1)', (pid, uuid_value := __import__('uuid').uuid4().hex))
            sku = cur.lastrowid
        conn.commit()
    with TestClient(app, raise_server_exceptions=False) as setup:
        created = setup.post('/order/create', json={'user_id':users[1],'delivery_way':'pickup','buy_now':True,'buy_now_items':[{'product_id':pid,'sku_id':sku,'quantity':1}]}, headers={'Authorization':'Bearer '+token(users[1])})
        assert created.status_code == 200
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT order_number FROM orders WHERE user_id=%s ORDER BY id DESC LIMIT 1', (users[1],))
            number = cur.fetchone()['order_number']
            cur.execute('UPDATE orders SET expire_at=DATE_SUB(NOW(),INTERVAL 1 SECOND) WHERE order_number=%s', (number,))
        conn.commit()
    locked = threading.Event()
    attempted = threading.Event()
    release = threading.Event()
    ids = []
    class Cursor:
        def __init__(self, cur, first): self.cur,self.first = cur,first
        def __enter__(self): return self
        def __exit__(self,*args): self.cur.close()
        def __getattr__(self,name): return getattr(self.cur,name)
        def execute(self,sql,args=None):
            target = 'FROM orders' in sql and 'FOR UPDATE' in sql
            if target and not self.first: attempted.set()
            result = self.cur.execute(sql,args)
            if target and self.first and not locked.is_set():
                locked.set()
                assert release.wait(15)
            return result
    class Connection:
        def __init__(self,conn,first): self.conn,self.first=conn,first
        def __getattr__(self,name): return getattr(self.conn,name)
        def cursor(self): return Cursor(self.conn.cursor(),self.first)
    def connection(first):
        @contextmanager
        def connect():
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute('SELECT CONNECTION_ID() AS id')
                    ids.append(cur.fetchone()['id'])
                yield Connection(conn,first)
        return connect
    monkeypatch.setattr(routes,'get_conn',connection(pay_first))
    monkeypatch.setattr(order,'get_conn',connection(not pay_first))
    # Invoke real payment handler via independent HTTP portal and actual expiry business function.
    import asyncio
    data={'out_trade_no':number,'transaction_id':'TX'+uuid_value,'amount':{'total':100,'currency':'CNY'}}
    def pay():
        try:
            asyncio.run(routes.handle_transaction_success(data))
            return True
        except ValueError:
            return False
    def expire(): return order._cancel_expire_orders_once()
    with ThreadPoolExecutor(2) as pool:
        first=pool.submit(pay if pay_first else expire)
        assert locked.wait(15)
        second=pool.submit(expire if pay_first else pay)
        assert attempted.wait(15)
        assert len(set(ids))>=2
        release.set()
        first.result(30)
        second.result(30)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM orders WHERE order_number=%s',(number,))
            state=cur.fetchone()['status']
            assert state == ('pending_recv' if pay_first else 'cancelled')
            cur.execute('SELECT stock FROM product_skus WHERE id=%s',(sku,))
            assert cur.fetchone()['stock'] == (0 if pay_first else 1)
    evidence({'pay_first':pay_first,'connections':ids,'final':state})
