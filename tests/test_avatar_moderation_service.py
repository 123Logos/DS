import io
import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import HTTPException, UploadFile
from PIL import Image

from models.schemas.user import UpdateProfileReq
from services import avatar_moderation_service as avatar_module
from services import wechat_api
from services.avatar_moderation_service import AvatarModerationService


def _upload(filename: str, image_bytes: bytes) -> UploadFile:
    return UploadFile(filename=filename, file=io.BytesIO(image_bytes))


def _png_bytes() -> bytes:
    output = io.BytesIO()
    Image.new("RGB", (12, 8), "white").save(output, format="PNG")
    return output.getvalue()


def test_normalize_image_validates_real_content(tmp_path: Path):
    target = tmp_path / "avatar.jpg"
    AvatarModerationService._normalize_image(_upload("avatar.png", _png_bytes()), _png_bytes(), target)

    with Image.open(target) as image:
        assert image.format == "JPEG"
        assert image.size == (12, 8)


def test_normalize_image_rejects_renamed_non_image(tmp_path: Path):
    with pytest.raises(HTTPException) as exc_info:
        AvatarModerationService._normalize_image(
            _upload("avatar.png", b"not-an-image"),
            b"not-an-image",
            tmp_path / "avatar.jpg",
        )
    assert exc_info.value.status_code == 400


def test_media_path_is_confined_to_pending_directory(tmp_path: Path):
    root = tmp_path / "pending"
    root.mkdir()
    assert avatar_module._safe_path(str(root / "avatar.jpg"), root) == (root / "avatar.jpg").resolve()
    assert avatar_module._safe_path(str(root.parent / "outside.jpg"), root) is None


def test_update_profile_cannot_bypass_avatar_review():
    from api.user.routes import update_profile

    with pytest.raises(HTTPException) as exc_info:
        update_profile(UpdateProfileReq(mobile="13800000000", avatar_path="/pic/avatars/unsafe.jpg"))
    assert exc_info.value.status_code == 400


def test_wechat_media_check_async_builds_expected_request(monkeypatch):
    captured = {}

    async def fake_access_token(*, force_refresh=False):
        return "access-token"

    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"errcode": 0, "trace_id": "trace-123"}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def post(self, url, json, timeout):
            captured.update(url=url, payload=json, timeout=timeout)
            return FakeResponse()

    monkeypatch.setattr(wechat_api, "get_access_token", fake_access_token)
    monkeypatch.setattr(wechat_api.httpx, "AsyncClient", FakeClient)

    trace_id = asyncio.run(
        wechat_api.media_check_async(
            media_url="https://api.example.com/wechat-wxa/media/avatar/token",
            openid="openid-1",
            scene=1,
        )
    )

    assert trace_id == "trace-123"
    assert captured["url"] == "https://api.weixin.qq.com/wxa/media_check_async?access_token=access-token"
    assert captured["payload"] == {
        "media_url": "https://api.example.com/wechat-wxa/media/avatar/token",
        "media_type": 2,
        "version": 2,
        "scene": 1,
        "openid": "openid-1",
    }


class _CallbackCursor:
    def __init__(self, state: dict, pending_path: Path):
        self.state = state
        self.pending_path = pending_path
        self.rowcount = 0
        self.last_sql = ""

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=()):
        self.last_sql = " ".join(str(sql).split()).lower()
        if "set status=%s" in self.last_sql and "where batch_id" not in self.last_sql:
            self.state["status"] = params[0]
        if "set status='expired'" in self.last_sql:
            self.state["status"] = "expired"

    def fetchone(self):
        if "from avatar_review_submissions where trace_id" in self.last_sql:
            return {
                "id": 9,
                "batch_id": "batch-1",
                "user_id": 7,
                "status": self.state["status"],
                "trace_id": "trace-1",
                "pending_file_path": str(self.pending_path),
                "expires_at": datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(minutes=5),
            }
        return None

    def fetchall(self):
        if "select pending_file_path" in self.last_sql:
            return [{"pending_file_path": str(self.pending_path)}]
        if "select * from avatar_review_submissions where batch_id" in self.last_sql:
            return []
        return []


class _CallbackConnection:
    def __init__(self, state: dict, pending_path: Path):
        self.cursor_obj = _CallbackCursor(state, pending_path)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        pass


def test_risky_callback_removes_the_triggering_file_and_is_idempotent(monkeypatch, tmp_path: Path):
    pending = tmp_path / "avatar_pending.jpg"
    pending.write_bytes(b"image")
    state = {"status": "pending"}
    cleaned: list[Path] = []

    monkeypatch.setattr(avatar_module, "AVATAR_PENDING_DIR", tmp_path)
    monkeypatch.setattr(avatar_module, "get_conn", lambda: _CallbackConnection(state, pending))

    def record_once(paths):
        for path in paths:
            if path not in cleaned:
                cleaned.append(path)

    monkeypatch.setattr(
        AvatarModerationService,
        "_cleanup_paths",
        staticmethod(record_once),
    )

    callback = {"trace_id": "trace-1", "errcode": 0, "result": {"suggest": "risky", "label": 10001}}
    AvatarModerationService.handle_result(callback)
    AvatarModerationService.handle_result(callback)

    assert state["status"] == "risky"
    assert cleaned == [pending]
