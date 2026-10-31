import threading
import uuid
from contextlib import contextmanager


def test_last_stock_two_actual_http_buyers(db, http, users, token, monkeypatch, race, evidence):
    from api.order import order
    from core.database import get_conn
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO products(name,user_id,status) VALUES('Synthetic stock item',%s,1)", (users[2],))
            product_id = cur.lastrowid
            cur.execute('INSERT INTO product_skus(product_id,sku_code,price,stock) VALUES(%s,%s,9.99,1)',
                (product_id, uuid.uuid4().hex))
            sku_id = cur.lastrowid
        conn.commit()
    # Both business transactions own distinct real connections before either can select stock.
    barrier = threading.Barrier(2)
    identities = []
    @contextmanager
    def coordinated_conn():
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT CONNECTION_ID() id')
                identities.append(cur.fetchone()['id'])
            barrier.wait(timeout=15)
            yield conn
    monkeypatch.setattr(order, 'get_conn', coordinated_conn)
    credentials = {uid: token(uid) for uid in (users[1], users[3])}
    def buy(uid):
        return http.post('/order/create', headers={'Authorization': 'Bearer ' + credentials[uid]},
            json={'user_id': uid, 'delivery_way': 'pickup', 'buy_now': True,
                'buy_now_items': [{'product_id': product_id, 'sku_id': sku_id, 'quantity': 1, 'price': 0.01}]})
    responses = race(lambda: buy(users[1]), lambda: buy(users[3]))
    assert len(set(identities)) == 2
    assert sum(r.status_code == 200 for r in responses) == 1
    assert all(r.status_code in (200, 400, 409, 422) for r in responses)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT stock FROM product_skus WHERE id=%s', (sku_id,))
            assert cur.fetchone()['stock'] == 0
            cur.execute('SELECT COUNT(*) n, SUM(quantity) quantity FROM order_items WHERE sku_id=%s', (sku_id,))
            row = cur.fetchone()
            assert row['n'] == row['quantity'] == 1
            cur.execute('SELECT total_amount FROM orders WHERE user_id IN (%s,%s)', (users[1], users[3]))
            rows = cur.fetchall()
            assert len(rows) == 1 and str(rows[0]['total_amount']) == '9.99'
    evidence({'connections': identities, 'statuses': [r.status_code for r in responses],
        'stock': 0, 'order_items': 1, 'authoritative_price': '9.99'})
