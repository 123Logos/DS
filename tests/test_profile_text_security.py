import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.user import routes
from services import wechat_api


@pytest.fixture
def profile_client(monkeypatch):
    app = FastAPI()
    routes.register_routes(app)
    app.dependency_overrides[routes.get_current_user] = lambda: {
        "id": 7, "mobile": "13800000000", "openid": "owner"
    }
    writes = []
    monkeypatch.setattr(routes, "_update_profile", lambda *args: writes.append(args) or {"msg": "ok"})
    with TestClient(app) as client:
        yield client, writes


@pytest.mark.parametrize("reply,status", [
    ({"errcode": 0, "result": {"suggest": "risky"}}, 400),
    ({"errcode": 0, "result": {"suggest": "review"}}, 400),
    ({"errcode": 45009}, 503),
])
def test_direct_profile_write_requires_review(profile_client, monkeypatch, reply, status):
    async def check(*args, **kwargs):
        return reply

    monkeypatch.setattr(wechat_api, "msg_sec_check", check)
    client, writes = profile_client
    response = client.post('/user/update-profile', json={"mobile": "13800000000", "name": "违规昵称"})
    assert response.status_code == status
    assert writes == []


def test_profile_cannot_target_other_mobile(profile_client):
    client, writes = profile_client
    response = client.post('/user/update-profile', json={"mobile": "13900000000", "name": "昵称"})
    assert response.status_code == 403
    assert writes == []


def test_profile_authentication_required():
    app = FastAPI()
    routes.register_routes(app)
    with TestClient(app) as client:
        response = client.post('/user/update-profile', json={"mobile": "13800000000", "name": "昵称"})
    assert response.status_code == 401


def test_missing_openid_cannot_write_name(profile_client):
    client, writes = profile_client
    client.app.dependency_overrides[routes.get_current_user] = lambda: {
        "id": 7, "mobile": "13800000000", "openid": ""
    }
    response = client.post('/user/update-profile', json={"mobile": "13800000000", "name": "昵称"})
    assert response.status_code == 503
    assert writes == []


class _EmptyConnection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def cursor(self):
        return self

    def execute(self, *args):
        pass

    def fetchone(self):
        return None

    def commit(self):
        pass


def test_legacy_registration_cannot_publish_unreviewed_name(monkeypatch):
    from models.schemas.user import AuthReq
    from fastapi import HTTPException

    monkeypatch.setattr(routes, "get_conn", _EmptyConnection)
    monkeypatch.setattr(routes, "build_dynamic_select", lambda *a, **kw: "SELECT synthetic")
    registered = []
    monkeypatch.setattr(routes.UserService, "register", lambda **kw: registered.append(kw))
    with pytest.raises(HTTPException) as error:
        routes.user_auth(AuthReq(mobile="13800000000", password="synthetic", name="unreviewed"))
    assert error.value.status_code == 400
    assert registered == []


@pytest.mark.parametrize("verdict,status", [("risky", 400), ("review", 400), ("pass", 200)])
def test_new_wechat_user_requires_nickname_verdict(monkeypatch, verdict, status):
    monkeypatch.setattr(routes, "get_conn", _EmptyConnection)
    monkeypatch.setattr(routes.WechatService, "get_openid_by_code", lambda code: "verified-owner")
    monkeypatch.setattr(routes.WechatService, "check_user_by_openid", lambda openid: None)
    registered = []
    monkeypatch.setattr(routes.WechatService, "register_user", lambda *args: registered.append(args) or 7)
    monkeypatch.setattr(routes, "create_access_token", lambda *args, **kw: "synthetic-business-token")

    async def check(content, **kwargs):
        assert kwargs["openid"] == "verified-owner"
        return {"errcode": 0, "result": {"suggest": verdict}}

    monkeypatch.setattr(wechat_api, "msg_sec_check", check)
    app = FastAPI()
    routes.register_routes(app)
    with TestClient(app) as client:
        response = client.post('/wechat/login', json={"code": "synthetic-code", "nickName": "昵称"})
    assert response.status_code == status
    if verdict == "pass":
        assert registered == [("verified-owner", "昵称")]
        assert response.json()["is_new"] is True
    else:
        assert registered == []
