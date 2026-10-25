"""Real app/MySQL tests. SMS replacement proves local control flow, not delivery."""
from datetime import datetime, timedelta
import jwt
import pytest


def _mobile(db, uid):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT mobile FROM users WHERE id=%s', (uid,))
            return cur.fetchone()['mobile']


def test_user_privacy_actual_routes(http, users, token, db, monkeypatch):
    from core.config import settings
    monkeypatch.setattr(settings, 'ADMIN_USER_IDS', str(users[3]))
    headers = {'Authorization': 'Bearer ' + token(users[0], 'jwt')}
    mobile = _mobile(db, users[1])
    for path in ['/user/info', '/user/refer-direct', '/user/refer-team', '/user/unilevel', '/reward/list', '/address/return']:
        assert http.get(path, params={'mobile': mobile}, headers=headers).status_code == 403
        assert http.get(path, params={'mobile': mobile}).status_code == 401
    for path in ['/user/referral-qr', '/unilevel/status', '/all-points']:
        assert http.get(path, params={'user_id':users[1]}, headers=headers).status_code == 403
        assert http.get(path, params={'user_id':users[1]}).status_code == 401
    assert http.post('/user/get-phone', json={'user_id':users[1], 'code':'synthetic'}, headers=headers).status_code == 403
    assert http.get('/user/list', headers=headers).status_code == 403
    assert http.post('/user/grant-merchant', params={'mobile':mobile,'admin_key':'forged'}, headers=headers).status_code == 403


def test_reset_single_consumer_and_all_sessions_revoked(http, users, token, db, race, monkeypatch, evidence):
    from services import auth_security_service as service
    from core.config import settings
    monkeypatch.setattr(settings, 'ENABLE_UUID_AUTH', 1)
    import core.auth as auth
    monkeypatch.setattr(auth, 'ENABLE_UUID_AUTH', 1)
    codes = []
    monkeypatch.setattr(service, 'send_sms', lambda mobile, code, purpose, request_id: codes.append(code) or 'controlled-boundary-message')
    mobile = _mobile(db, users[0])
    tokens = [token(users[0], kind) for kind in ['jwt','uuid','wechat']]
    other = token(users[1], 'jwt')
    result = http.post('/user/reset-password/sms', json={'mobile':mobile,'device_id':'synthetic-device-00001'})
    assert result.status_code == 200
    assert 'mock_code' not in result.json()
    body = {'mobile':mobile,'sms_code':codes[0],'new_password':'New-synthetic-pass-42!'}
    results = race(lambda: http.post('/user/reset-password',json=body), lambda: http.post('/user/reset-password',json=body))
    assert sorted(r.status_code for r in results) == [200,400]
    for value in tokens:
        assert http.get('/user/info',params={'mobile':mobile},headers={'Authorization':'Bearer '+value}).status_code == 401
    assert http.get('/user/info',params={'mobile':_mobile(db,users[1])},headers={'Authorization':'Bearer '+other}).status_code == 200
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) n FROM sessions WHERE user_id=%s',(users[0],))
            assert cur.fetchone()['n'] == 0
            cur.execute("SELECT COUNT(*) n FROM security_operator_audit WHERE target_id=%s AND action='password_reset'",(users[0],))
            assert cur.fetchone()['n'] == 1
    evidence({'provider_boundary':'controlled adapter; not real provider proof','reset_statuses':[r.status_code for r in results]})


def test_attempt_limit_survives_reissue(http, users, db, monkeypatch):
    from services import auth_security_service as service
    codes=[]
    monkeypatch.setattr(service,'send_sms',lambda mobile,code,purpose,request_id: codes.append(code) or 'controlled')
    mobile=_mobile(db,users[0])
    assert http.post('/user/reset-password/sms',json={'mobile':mobile,'device_id':'attempt-device-00001'}).status_code == 200
    for _ in range(5):
        assert http.post('/user/reset-password',json={'mobile':mobile,'sms_code':'000000' if codes[0]!='000000' else '111111','new_password':'Attempt-synthetic42!'}).status_code == 400
    assert http.post('/user/reset-password',json={'mobile':mobile,'sms_code':codes[0],'new_password':'Attempt-synthetic42!'}).status_code == 400
    assert http.post('/user/reset-password/sms',json={'mobile':mobile,'device_id':'another-device-00001'}).status_code == 429


def test_legacy_jwt_and_logout(http, users, token, db):
    from core.auth import invalidate_token
    from core.config import JWT_SECRET_KEY, JWT_ALGORITHM
    mobile=_mobile(db,users[0])
    old=jwt.encode({'user_id':users[0],'exp':datetime.utcnow()+timedelta(minutes=5)},JWT_SECRET_KEY,algorithm=JWT_ALGORITHM)
    assert http.get('/user/info',params={'mobile':mobile},headers={'Authorization':'Bearer '+old}).status_code == 401
    current=token(users[0],'jwt')
    assert invalidate_token(current)
    assert http.get('/user/info',params={'mobile':mobile},headers={'Authorization':'Bearer '+current}).status_code == 401


def test_reset_rolls_back_code_when_audit_fails(http, users, db, monkeypatch):
    from services import auth_security_service as service
    import api.user.routes as routes
    codes=[]
    monkeypatch.setattr(service,'send_sms',lambda mobile,code,purpose,request_id: codes.append(code) or 'controlled')
    mobile=_mobile(db,users[0])
    assert http.post('/user/reset-password/sms',json={'mobile':mobile,'device_id':'rollback-device-0001'}).status_code == 200
    real_audit=routes.audit
    def fail(*args,**kwargs):
        raise RuntimeError('synthetic precommit failure')
    monkeypatch.setattr(routes,'audit',fail)
    body={'mobile':mobile,'sms_code':codes[0],'new_password':'Rollback-synthetic42!'}
    assert http.post('/user/reset-password',json=body).status_code == 500
    monkeypatch.setattr(routes,'audit',real_audit)
    assert http.post('/user/reset-password',json=body).status_code == 200

def test_real_provider_adapter_signs_controlled_http(monkeypatch):
    from services import auth_security_service as service
    from core.config import settings
    from pydantic import SecretStr
    for name,value in {'SMS_SECRET_ID':'synthetic-id','SMS_SECRET_KEY':SecretStr('synthetic-secret'),
                       'SMS_SDK_APP_ID':'synthetic-app','SMS_SIGN_NAME':'synthetic-sign','SMS_RESET_TEMPLATE_ID':'synthetic-template'}.items():
        monkeypatch.setattr(settings,name,value)
    calls=[]
    class Response:
        def raise_for_status(self):
            return None
        def json(self):
            return {'Response':{'SendStatusSet':[{'Code':'Ok','SerialNo':'synthetic-message'}]}}
    def post(url,**kwargs):
        calls.append((url,kwargs))
        return Response()
    monkeypatch.setattr(service.requests,'post',post)
    assert service.send_sms('19900000001','382746','password_reset','a'*32) == 'synthetic-message'
    url,request=calls[0]
    assert url == 'https://sms.tencentcloudapi.com/'
    assert request['headers']['Authorization'].startswith('TC3-HMAC-SHA256 Credential=synthetic-id/')
    assert request['headers']['X-TC-Action'] == 'SendSms'
    assert b'382746' in request['data']
    assert request['timeout'] > 0


def test_expiry_purpose_subject_and_resend_limits(http, users, db, monkeypatch):
    from services import auth_security_service as service
    codes=[]
    monkeypatch.setattr(service,'send_sms',lambda mobile,code,purpose,request_id: codes.append(code) or 'controlled')
    mobile=_mobile(db,users[0])
    first=service.issue_sms(mobile,'password_reset',mobile,'expiry-ip','expiry-device')
    with db() as conn:
        with conn.cursor() as cur:
            assert not service.consume_sms(cur,mobile,'bankcard_bind',mobile,codes[0],first['session_id'])
            assert not service.consume_sms(cur,_mobile(db,users[1]),'password_reset',mobile,codes[0],first['session_id'])
            cur.execute('UPDATE auth_sms_challenges SET expires_at=DATE_SUB(NOW(),INTERVAL 1 SECOND) WHERE session_id=%s',(first['session_id'],))
            conn.commit()
    assert http.post('/user/reset-password',json={'mobile':mobile,'sms_code':codes[0],'new_password':'Expiry-synthetic42!'}).status_code == 400
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE auth_sms_limits SET last_issued_at=DATE_SUB(NOW(),INTERVAL 61 SECOND) WHERE scope_hash=%s',(service.digest('mobile:'+mobile),))
            cur.execute('UPDATE auth_sms_limits SET attempt_count=5 WHERE scope_hash=%s',(service.digest('attempt:'+mobile+':password_reset'),))
        conn.commit()
    service.issue_sms(mobile,'password_reset',mobile,'expiry-ip','expiry-device')
    assert http.post('/user/reset-password',json={'mobile':mobile,'sms_code':codes[-1],'new_password':'Expiry-synthetic42!'}).status_code == 400

def test_operator_changes_have_atomic_trusted_audit(http, users, token, db, monkeypatch):
    from core.config import settings
    monkeypatch.setattr(settings,'ADMIN_USER_IDS',str(users[3]))
    headers={'Authorization':'Bearer '+token(users[3],'jwt')}
    mobile=_mobile(db,users[0])
    response=http.post('/user/set-level',json={'mobile':mobile,'new_level':2,'reason':'synthetic operator adjustment'},headers=headers)
    assert response.status_code == 200
    response=http.post('/points',json={'mobile':mobile,'type':'member','amount':3,'reason':'synthetic points audit'},headers=headers)
    assert response.status_code == 200
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT operator_id,action,before_json,after_json FROM security_operator_audit WHERE target_id=%s AND action IN ('set_member_level','points_adjustment') ORDER BY id",(users[0],))
            rows=cur.fetchall()
            assert len(rows) == 2
            assert all(row['operator_id'] == users[3] for row in rows)
            cur.execute('SELECT operator_id,balance_before,balance_after,event_id,source FROM points_log WHERE user_id=%s',(users[0],))
            row=cur.fetchone()
            assert row['operator_id'] == users[3] and row['source'] == 'admin'
            assert row['balance_after']-row['balance_before'] == 3
            assert row['event_id']

def test_registration_cannot_issue_after_password_changed(http, db, monkeypatch):
    import secrets
    import api.user.routes as routes
    from services.user_service import hash_pwd
    mobile='199'+str(secrets.randbelow(100000000)).zfill(8)
    original=routes.UserService.register
    def register_then_reset(*args,**kwargs):
        uid=original(*args,**kwargs)
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute('UPDATE users SET password_hash=%s WHERE id=%s',(hash_pwd('Changed-synthetic42!'),uid))
            conn.commit()
        return uid
    monkeypatch.setattr(routes.UserService,'register',register_then_reset)
    result=http.post('/user/auth',json={'mobile':mobile,'password':'Original-synthetic42!'})
    assert result.status_code == 401
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) n FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.mobile=%s',(mobile,))
            assert cur.fetchone()['n'] == 0


def test_locked_mobile_identity_rejects_stale_login(users, db, token):
    from core.auth import create_access_token
    from fastapi import HTTPException
    old=_mobile(db,users[0])
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET mobile=%s WHERE id=%s',('188'+old[3:],users[0]))
        conn.commit()
    with pytest.raises(HTTPException) as error:
        create_access_token(users[0],'jwt',expected_mobile=old,expected_password='Synthetic-pass-42!')
    assert error.value.status_code == 401


def test_reset_waits_for_mobile_move_then_rejects_old_identity(http, users, db, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event
    from services import auth_security_service as service
    import api.user.routes as routes
    codes=[]
    monkeypatch.setattr(service,'send_sms',lambda mobile,code,purpose,request_id: codes.append(code) or 'controlled')
    mobile=_mobile(db,users[0])
    assert http.post('/user/reset-password/sms',json={'mobile':mobile,'device_id':'mobile-race-device-0001'}).status_code == 200
    reached=Event()
    original=routes.build_dynamic_select
    def select(*args,**kwargs):
        result=original(*args,**kwargs)
        reached.set()
        return result
    monkeypatch.setattr(routes,'build_dynamic_select',select)
    with db() as mover:
        with mover.cursor() as cur:
            cur.execute('SELECT id FROM users WHERE id=%s FOR UPDATE',(users[0],))
            cur.execute('UPDATE users SET mobile=%s WHERE id=%s',('177'+mobile[3:],users[0]))
        with ThreadPoolExecutor(max_workers=1) as pool:
            future=pool.submit(http.post,'/user/reset-password',json={'mobile':mobile,'sms_code':codes[0],'new_password':'Move-race-synthetic42!'})
            assert reached.wait(15)
            mover.commit()
            assert future.result(timeout=30).status_code == 400

def test_reset_code_cannot_follow_reassigned_mobile(http, users, db, monkeypatch):
    from services import auth_security_service as service
    codes=[]
    monkeypatch.setattr(service,'send_sms',lambda mobile,code,purpose,request_id: codes.append(code) or 'controlled')
    mobile=_mobile(db,users[0])
    assert http.post('/user/reset-password/sms',json={'mobile':mobile,'device_id':'reassign-device-00001'}).status_code == 200
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET mobile=%s WHERE id=%s',('166'+mobile[3:],users[0]))
            cur.execute('UPDATE users SET mobile=%s WHERE id=%s',(mobile,users[1]))
        conn.commit()
    assert http.post('/user/reset-password',json={'mobile':mobile,'sms_code':codes[0],'new_password':'Reassign-synthetic42!'}).status_code == 400

def test_system_role_grant_requires_admin_and_audit(http, users, token, db, monkeypatch):
    from core.config import settings
    monkeypatch.setattr(settings,'ADMIN_USER_IDS',str(users[3]))
    params={'user_id':users[0],'is_merchant':2,'key':'forged-legacy-key'}
    assert http.post('/api/system/grant-system',params=params).status_code == 401
    ordinary={'Authorization':'Bearer '+token(users[1],'jwt')}
    assert http.post('/api/system/grant-system',params=params,headers=ordinary).status_code == 403
    assert http.put('/api/system/sentences',json={'system_sentence':'synthetic'},headers=ordinary).status_code == 403
    admin={'Authorization':'Bearer '+token(users[3],'jwt')}
    assert http.post('/api/system/grant-system',params={**params,'is_merchant':3},headers=admin).status_code == 422
    assert http.post('/api/system/grant-system',params=params,headers=admin).status_code == 200
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT is_merchant FROM users WHERE id=%s',(users[0],))
            assert cur.fetchone()['is_merchant'] == 2
            cur.execute("SELECT operator_id,before_json,after_json FROM security_operator_audit WHERE target_id=%s AND action='system_grant_role'",(users[0],))
            rows=cur.fetchall()
            assert len(rows) == 1 and rows[0]['operator_id'] == users[3]

def test_new_registration_is_normal_and_frozen_account_stays_denied(http, users, db):
    import secrets
    from services.wechat_service import WechatService
    mobile='199'+str(secrets.randbelow(100000000)).zfill(8)
    response=http.post('/user/auth',json={'mobile':mobile,'password':'Fresh-synthetic42!'})
    assert response.status_code == 200
    assert response.json()['is_new'] is True
    fresh=response.json()['uid']
    wechat=WechatService.register_user('synthetic_'+secrets.token_hex(12),'微信用户')
    frozen_mobile=_mobile(db,users[0])
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT id,status FROM users WHERE id IN (%s,%s)',(fresh,wechat))
            assert all(row['status'] == 0 for row in cur.fetchall())
            cur.execute('UPDATE users SET status=1 WHERE id=%s',(users[0],))
        conn.commit()
    assert http.post('/user/auth',json={'mobile':frozen_mobile,'password':'Synthetic-pass-42!'}).status_code == 403
    from core.auth import create_access_token
    from fastapi import HTTPException
    with pytest.raises(HTTPException) as error:
        create_access_token(users[0],'jwt')
    assert error.value.status_code == 403
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT status FROM users WHERE id=%s',(users[0],))
            assert cur.fetchone()['status'] == 1

def test_reset_allows_fresh_login_and_independent_app_rejects_old(http, users, token, db, monkeypatch):
    from fastapi import FastAPI, Depends
    from fastapi.testclient import TestClient
    from core.auth import get_current_user
    from services import auth_security_service as service
    codes=[]
    monkeypatch.setattr(service,'send_sms',lambda mobile,code,purpose,request_id: codes.append(code) or 'controlled')
    mobile=_mobile(db,users[0])
    old=token(users[0],'jwt')
    assert http.post('/user/reset-password/sms',json={'mobile':mobile,'device_id':'fresh-login-device-0001'}).status_code == 200
    assert http.post('/user/reset-password',json={'mobile':mobile,'sms_code':codes[0],'new_password':'Fresh-reset-synthetic42!'}).status_code == 200
    login=http.post('/user/auth',json={'mobile':mobile,'password':'Fresh-reset-synthetic42!'})
    assert login.status_code == 200
    app=FastAPI()
    @app.get('/identity')
    def identity(user=Depends(get_current_user)):
        return {'id':user['id']}
    with TestClient(app) as independent:
        assert independent.get('/identity',headers={'Authorization':'Bearer '+old}).status_code == 401
        assert independent.get('/identity',headers={'Authorization':'Bearer '+login.json()['token']}).json() == {'id':users[0]}


def test_auth_storage_outage_denies_request(http, users, token, db, monkeypatch):
    import core.auth as auth
    mobile=_mobile(db,users[0])
    value=token(users[0],'jwt')
    def unavailable():
        raise RuntimeError('synthetic auth storage unavailable')
    monkeypatch.setattr(auth,'get_conn',unavailable)
    assert http.get('/user/info',params={'mobile':mobile},headers={'Authorization':'Bearer '+value}).status_code == 503


@pytest.mark.parametrize('failure',['reject','timeout'])
def test_failed_reissue_is_unusable_and_supersedes_old_code(http, users, db, monkeypatch, failure):
    from services import auth_security_service as service
    from fastapi import HTTPException
    import requests
    codes=[]
    monkeypatch.setattr(service,'send_sms',lambda mobile,code,purpose,request_id: codes.append(code) or 'controlled')
    mobile=_mobile(db,users[0])
    body={'mobile':mobile,'device_id':'provider-failure-device-'+failure}
    assert http.post('/user/reset-password/sms',json=body).status_code == 200
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE auth_sms_limits SET last_issued_at=DATE_SUB(NOW(),INTERVAL 61 SECOND) WHERE scope_hash=%s',(service.digest('mobile:'+mobile),))
        conn.commit()
    def fail(mobile,code,purpose,request_id):
        codes.append(code)
        if failure == 'reject':
            raise HTTPException(503,'synthetic supplier rejection')
        raise requests.Timeout('synthetic boundary timeout')
    monkeypatch.setattr(service,'send_sms',fail)
    assert http.post('/user/reset-password/sms',json=body).status_code == 503
    for code in codes:
        assert http.post('/user/reset-password',json={'mobile':mobile,'sms_code':code,'new_password':'Provider-synthetic42!'}).status_code == 400
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('SELECT send_status,consumed_at FROM auth_sms_challenges WHERE mobile=%s ORDER BY id DESC LIMIT 1',(mobile,))
            row=cur.fetchone()
            assert row['send_status'] == ('rejected' if failure == 'reject' else 'unknown')
            assert row['consumed_at'] is None

def test_jwt_accepts_mysql_numeric_identity(users, db):
    from decimal import Decimal
    import jwt
    from core.auth import create_access_token
    from core.config import JWT_SECRET_KEY, JWT_ALGORITHM
    value=create_access_token(Decimal(users[0]),'jwt')
    payload=jwt.decode(value,JWT_SECRET_KEY,algorithms=[JWT_ALGORITHM])
    assert type(payload['user_id']) is int
    assert payload['user_id'] == users[0]

def test_registration_referrer_logs_exclude_sensitive_canaries(http, users, db):
    import logging
    import secrets
    from io import StringIO
    from core.logging import RequestIdFilter
    from services.user_service import UserService
    referrer=_mobile(db,users[1])
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute('UPDATE users SET member_level=1 WHERE id=%s',(users[1],))
        conn.commit()
    mobile='199'+str(secrets.randbelow(100000000)).zfill(8)
    referral_mobile='198'+str(secrets.randbelow(100000000)).zfill(8)
    password='REGISTRATION-PASSWORD-CANARY42!'
    authorization='REGISTRATION-AUTHORIZATION-CANARY'
    cookie='REGISTRATION-COOKIE-CANARY'
    stream=StringIO()
    handler=logging.StreamHandler(stream)
    handler.setLevel(logging.INFO)
    handler.addFilter(RequestIdFilter())
    handler.setFormatter(logging.Formatter('%(name)s %(levelname)s [%(request_id)s] %(message)s'))
    root=logging.getLogger()
    old_level=root.level
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    try:
        response=http.post('/user/auth',json={'mobile':mobile,'password':password},
            headers={'Authorization':'Bearer '+authorization,'Cookie':'synthetic='+cookie})
        assert response.status_code == 200
        # /user/auth intentionally has no referral parameter. Exercise its actual
        # registration service's referral branch separately, without a wiring mock.
        referral_id=UserService.register(referral_mobile,password,referrer_mobile=referrer)
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute('SELECT referrer_id FROM user_referrals WHERE user_id=%s',(referral_id,))
                assert cur.fetchone()['referrer_id'] == users[1]
        handler.flush()
        emitted=stream.getvalue()
        assert 'services.user_service INFO' in emitted
        assert 'security_operation_event' in emitted
        for canary in (mobile,referral_mobile,referrer,password,authorization,cookie):
            assert canary not in emitted
    finally:
        root.removeHandler(handler)
        root.setLevel(old_level)
        handler.close()
