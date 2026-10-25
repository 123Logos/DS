"""CONTROLLED_PROVIDER_BOUNDARY: real signed HTTP/MySQL, no external money."""
import uuid
from contextlib import contextmanager
from decimal import Decimal
import pytest
from test_payment_business import signed_callback


@pytest.mark.parametrize('stage', ['settlement', 'commit'])
def test_signed_offline_failure_rollback_and_replay(db, http, users, signed_callback, monkeypatch, stage, evidence):
    from api.wechat_pay import routes
    from services.offline_service import OfflineService
    from core.database import get_conn
    number = 'OFF' + uuid.uuid4().hex
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET member_points=0 WHERE id=%s', (users[1],))
            cur.execute("INSERT INTO offline_order(order_no,merchant_id,user_id,store_name,amount,paid_amount,status) VALUES(%s,%s,%s,'Synthetic',1000,1000,1)", (number, users[2], users[1]))
        conn.commit()
    data = {'out_trade_no': number, 'transaction_id': 'TX' + uuid.uuid4().hex, 'trade_state': 'SUCCESS', 'amount': {'total': 1000, 'currency': 'CNY'}}
    body, headers = signed_callback(data, 'TRANSACTION.SUCCESS')
    original = OfflineService.on_paid
    async def fail_settlement(*args, **kwargs):
        await original(*args, **kwargs)
        raise RuntimeError('ISOLATED_AFTER_ASSETS')
    class Connection:
        def __init__(self, conn): self.conn = conn
        def __getattr__(self, name): return getattr(self.conn, name)
        def commit(self): raise RuntimeError('ISOLATED_FINAL_COMMIT')
    @contextmanager
    def failed_connection():
        with get_conn() as conn:
            yield Connection(conn)
    if stage == 'settlement': monkeypatch.setattr(OfflineService, 'on_paid', fail_settlement)
    else: monkeypatch.setattr(routes, 'get_conn', failed_connection)
    assert http.post('/api/offline/zhifu/notify', content=body, headers=headers).status_code == 503
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM offline_order WHERE order_no=%s', (number,))
            assert cur.fetchone()['status'] == 1
            cur.execute('SELECT member_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['member_points'] == 0
            for table, column in [('orders','order_number'),('payment_events','order_number'),('payment_merchant_transfers','order_number')]:
                cur.execute(f'SELECT COUNT(*) AS n FROM {table} WHERE {column}=%s', (number,))
                assert cur.fetchone()['n'] == 0
    monkeypatch.setattr(OfflineService, 'on_paid', original)
    monkeypatch.setattr(routes, 'get_conn', get_conn)
    for _ in range(2):
        assert http.post('/api/offline/zhifu/notify', content=body, headers=headers).status_code == 204
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT member_points FROM users WHERE id=%s', (users[1],))
            assert cur.fetchone()['member_points'] == Decimal('10')
            cur.execute('SELECT COUNT(*) AS n FROM points_log WHERE user_id=%s AND reason=%s', (users[1], '线下订单支付获得积分: ' + number))
            assert cur.fetchone()['n'] == 1
            cur.execute('SELECT COUNT(*) AS n FROM payment_events WHERE order_number=%s', (number,))
            assert cur.fetchone()['n'] == 1
            cur.execute('SELECT state,attempts FROM payment_merchant_transfers WHERE order_number=%s', (number,))
            assert cur.fetchone() == {'state':'prepared','attempts':0}
    evidence({'scenario': 'offline-signed-fault-replay', 'fault':stage, 'points_after':'10', 'money_provider_calls':0})

def test_template_http200_rejection_not_marked_delivered(db,users,monkeypatch):
    from services import notify_service, payment_transfer_service
    from core.config import settings
    number='OFF'+uuid.uuid4().hex
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("INSERT INTO orders(order_number,user_id,merchant_id,total_amount,status) VALUES(%s,%s,%s,1,'completed')",(number,users[1],users[2]))
            cur.execute("INSERT INTO payment_merchant_transfers(order_number,merchant_id,beneficiary_openid,amount,out_batch_no,state) VALUES(%s,%s,'synthetic',80,%s,'finished')",(number,users[2],uuid.uuid4().hex))
        conn.commit()
    class Response:
        def raise_for_status(self): pass
        def json(self): return {'errcode':40001}
    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): pass
        async def post(self,*args,**kwargs): return Response()
    async def access(): return 'synthetic-token'
    monkeypatch.setattr(settings,'WX_MOCK_MODE','false')
    monkeypatch.setattr(notify_service,'_get_access_token',access)
    monkeypatch.setattr(notify_service.httpx,'AsyncClient',Client)
    with pytest.raises(RuntimeError):
        payment_transfer_service.recover_transfer(number)
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT state,notification_sent FROM payment_merchant_transfers WHERE order_number=%s',(number,))
            assert cur.fetchone()=={'state':'finished','notification_sent':0}

def seed_coupon_payment(db,users):
    number='OFF'+uuid.uuid4().hex
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET member_points=0 WHERE id=%s',(users[1],))
            cur.execute("INSERT INTO coupons(user_id,coupon_type,amount,status,valid_from,valid_to) VALUES(%s,'user',1,'unused',CURDATE(),DATE_ADD(CURDATE(),INTERVAL 7 DAY))",(users[1],))
            coupon=cur.lastrowid
            cur.execute("INSERT INTO offline_order(order_no,merchant_id,user_id,store_name,amount,paid_amount,coupon_discount,coupon_ids,status) VALUES(%s,%s,%s,'Synthetic',1100,1000,100,%s,1)",(number,users[2],users[1],'['+str(coupon)+']'))
        conn.commit()
    return number,coupon,{'out_trade_no':number,'transaction_id':'TX'+uuid.uuid4().hex,'trade_state':'SUCCESS','amount':{'total':1000,'currency':'CNY'}}


@pytest.mark.parametrize('sql_fragment',['UPDATE offline_order SET status=2','UPDATE users SET member_points','UPDATE coupons SET status','INSERT INTO payment_events'])
def test_signed_callback_sql_fault_is_atomic(db,http,users,signed_callback,monkeypatch,sql_fragment,evidence):
    from api.wechat_pay import routes
    from core.database import get_conn
    number,coupon,data=seed_coupon_payment(db,users)
    body,headers=signed_callback(data,'TRANSACTION.SUCCESS')
    reached=[]
    class Cursor:
        def __init__(self,cur): self.cur=cur
        def __enter__(self): return self
        def __exit__(self,*args): self.cur.close()
        def __getattr__(self,name): return getattr(self.cur,name)
        def execute(self,sql,args=None):
            result=self.cur.execute(sql,args)
            if sql_fragment in ' '.join(sql.split()):
                reached.append(True)
                raise RuntimeError('ISOLATED_SQL_STAGE_FAILURE')
            return result
    class Connection:
        def __init__(self,conn): self.conn=conn
        def __getattr__(self,name): return getattr(self.conn,name)
        def cursor(self,*args): return Cursor(self.conn.cursor(*args))
    @contextmanager
    def fault_connection():
        with get_conn() as conn: yield Connection(conn)
    monkeypatch.setattr(routes,'get_conn',fault_connection)
    assert http.post('/api/offline/zhifu/notify',content=body,headers=headers).status_code==503
    assert reached
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM offline_order WHERE order_no=%s',(number,))
            assert cur.fetchone()['status']==1
            cur.execute('SELECT status FROM coupons WHERE id=%s',(coupon,))
            assert cur.fetchone()['status']=='unused'
            cur.execute('SELECT member_points FROM users WHERE id=%s',(users[1],))
            assert cur.fetchone()['member_points']==0
            cur.execute('SELECT COUNT(*) AS n FROM payment_events WHERE order_number=%s',(number,))
            assert cur.fetchone()['n']==0
    monkeypatch.setattr(routes,'get_conn',get_conn)
    assert http.post('/api/offline/zhifu/notify',content=body,headers=headers).status_code==204
    evidence({'sql_failure_site':sql_fragment,'rollback':True,'replayed':True})


def test_signed_concurrent_replay_once_with_nonzero_assets(db,users,signed_callback,monkeypatch,evidence):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    from fastapi.testclient import TestClient
    from main import app
    from api.wechat_pay import routes
    from core.database import get_conn
    number,coupon,data=seed_coupon_payment(db,users)
    body,headers=signed_callback(data,'TRANSACTION.SUCCESS')
    barrier=threading.Barrier(2)
    ids=[]
    @contextmanager
    def coordinated():
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT CONNECTION_ID() AS id')
                ids.append(cur.fetchone()['id'])
            barrier.wait(15)
            yield conn
    monkeypatch.setattr(routes,'get_conn',coordinated)
    with TestClient(app,raise_server_exceptions=False) as a,TestClient(app,raise_server_exceptions=False) as b:
        with ThreadPoolExecutor(2) as pool:
            results=[pool.submit(client.post,'/api/offline/zhifu/notify',content=body,headers=headers) for client in (a,b)]
            assert [result.result(30).status_code for result in results]==[204,204]
    assert len(set(ids))==2
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT member_points FROM users WHERE id=%s',(users[1],))
            assert cur.fetchone()['member_points']==10
            cur.execute('SELECT status FROM coupons WHERE id=%s',(coupon,))
            assert cur.fetchone()['status']=='used'
            cur.execute('SELECT COUNT(*) AS n FROM points_log WHERE user_id=%s AND reason=%s',(users[1],'线下订单支付获得积分: '+number))
            assert cur.fetchone()['n']==1
            cur.execute('SELECT COUNT(*) AS n FROM payment_events WHERE order_number=%s',(number,))
            assert cur.fetchone()['n']==1
            cur.execute('SELECT COUNT(*) AS n FROM payment_merchant_transfers WHERE order_number=%s',(number,))
            assert cur.fetchone()['n']==1
            cur.execute('SELECT COUNT(*) AS n,SUM(change_amount) AS amount FROM account_flow WHERE account_type=%s AND remark=%s',('platform_revenue_pool','线下订单收入: '+number))
            income=cur.fetchone()
            assert income['n']==1
            assert income['amount']==Decimal('11')
    evidence({'signed_concurrent_replay_connections':ids,'points':10,'events':1,'outbox':1})


@pytest.mark.parametrize('invalid',['merchant','amount','currency'])
def test_signed_wrong_binding_has_no_mutation(db,http,users,signed_callback,monkeypatch,invalid):
    from core.config import settings
    number,coupon,data=seed_coupon_payment(db,users)
    if invalid=='amount': data['amount']['total']=999
    if invalid=='currency': data['amount']['currency']='USD'
    body,headers=signed_callback(data,'TRANSACTION.SUCCESS')
    if invalid=='merchant': monkeypatch.setattr(settings,'WECHAT_PAY_MCH_ID','OTHER_MERCHANT')
    assert http.post('/api/offline/zhifu/notify',content=body,headers=headers).status_code==400
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM offline_order WHERE order_no=%s',(number,))
            assert cur.fetchone()['status']==1
            cur.execute('SELECT member_points FROM users WHERE id=%s',(users[1],))
            assert cur.fetchone()['member_points']==0
            cur.execute('SELECT status FROM coupons WHERE id=%s',(coupon,))
            assert cur.fetchone()['status']=='unused'

