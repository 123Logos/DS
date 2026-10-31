import asyncio

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.security import routes
from services import wechat_api


@pytest.fixture
def client(monkeypatch):
    app = FastAPI()
    routes.register_security_routes(app)
    app.dependency_overrides[routes.get_current_user] = lambda: {
        "id": 7, "openid": "openid-owner", "mobile": "13800000000"
    }
    with TestClient(app) as client:
        yield client


@pytest.mark.parametrize("reply,allowed", [
    ({"errcode": 0, "result": {"suggest": "pass"}}, True),
    ({"errcode": 0, "result": {"suggest": "risky"}}, False),
    ({"errcode": 0, "result": {"suggest": "review"}}, False),
    ({"errcode": 87014}, False),
    ({"errcode": 45009}, False),
    ({"errcode": 61010}, False),
    ({}, False),
    ({"errcode": 0}, False),
    ({"errcode": 0, "result": {"suggest": "unknown"}}, False),
    ({"errcode": "0", "result": {"suggest": "pass"}}, False),
    ({"errcode": False, "result": {"suggest": "pass"}}, False),
    ({"errcode": 0, "result": []}, False),
    ([], False),
    (None, False),
])
def test_only_explicit_v2_pass_allows_publication(client, monkeypatch, reply, allowed):
    async def fake_check(*args, **kwargs):
        return reply

    monkeypatch.setattr(wechat_api, "msg_sec_check", fake_check)
    response = client.post("/api/security/msg-sec-check", json={"content": "消费回馈"})
    assert response.status_code == 200
    assert response.json()["pass"] is allowed


def test_upstream_timeout_is_not_permission(client, monkeypatch, caplog):
    async def unavailable(*args, **kwargs):
        raise httpx.ReadTimeout("https://api.weixin.qq.com/?access_token=SECRET-CANARY")

    monkeypatch.setattr(wechat_api, "msg_sec_check", unavailable)
    response = client.post("/api/security/msg-sec-check", json={"content": "消费回馈"})
    assert response.status_code == 200
    assert response.json()["pass"] is False
    assert "SECRET-CANARY" not in caplog.text


def test_openid_cannot_impersonate_another_user(client, monkeypatch):
    calls = []

    async def fake_check(content, **kwargs):
        calls.append(kwargs)
        return {"errcode": 0, "result": {"suggest": "pass"}}

    monkeypatch.setattr(wechat_api, "msg_sec_check", fake_check)
    response = client.post("/api/security/msg-sec-check", json={
        "content": "消费回馈", "openid": "openid-victim"
    })
    assert response.status_code == 200
    assert response.json()["pass"] is False
    assert calls == []


@pytest.mark.parametrize("body", [
    {"content": " "}, {"content": "x" * 2501}, {"content": "hi", "scene": 5},
    {"content": "hi", "scene": True}, {"content": "hi", "scene": "1"},
])
def test_invalid_content_does_not_reach_wechat(client, monkeypatch, body):
    async def forbidden(*args, **kwargs):
        pytest.fail("invalid input reached WeChat")

    monkeypatch.setattr(wechat_api, "msg_sec_check", forbidden)
    response = client.post("/api/security/msg-sec-check", json=body)
    assert response.status_code == 422


def test_missing_authentication_is_rejected():
    app = FastAPI()
    routes.register_security_routes(app)
    with TestClient(app) as client:
        response = client.post("/api/security/msg-sec-check", json={"content": "hi"})
    assert response.status_code == 401


@pytest.mark.parametrize("content,openid", [("hi", ""), (" ", "owner"), ("x" * 2501, "owner")])
def test_service_rejects_invalid_input_before_token_fetch(monkeypatch, content, openid):
    async def forbidden(**kwargs):
        pytest.fail("invalid input fetched token")

    monkeypatch.setattr(wechat_api, "get_access_token", forbidden)
    with pytest.raises(ValueError):
        asyncio.run(wechat_api.msg_sec_check(content, openid=openid))


def test_http_client_log_does_not_expose_access_token():
    import io
    import logging
    from core.logging import RequestIdFilter

    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.addFilter(RequestIdFilter())
    record = logging.LogRecord("httpx", logging.INFO, __file__, 1,
        'HTTP Request: %s %s "HTTP/1.1 200 OK"',
        ("POST", "https://api.weixin.qq.com/wxa/msg_sec_check?access_token=SECRET-CANARY&x=1"), None)
    handler.handle(record)
    assert "SECRET-CANARY" not in output.getvalue()
    assert "access_token=[REDACTED]&x=1" in output.getvalue()


def test_missing_user_openid_fails_closed(client):
    client.app.dependency_overrides[routes.get_current_user] = lambda: {"id": 7}
    response = client.post("/api/security/msg-sec-check", json={"content": "消费回馈"})
    assert response.status_code == 200
    assert response.json()["pass"] is False
