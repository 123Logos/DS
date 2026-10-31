import asyncio

import pytest
from fastapi import HTTPException

from api.product import routes


def test_nested_public_texts_are_individually_reviewed_without_aggregate_limit(monkeypatch):
    calls = []

    async def review(text, **kwargs):
        calls.append(text)

    monkeypatch.setattr(routes, "require_safe_text", review)
    nested = {"尺寸": ["中" * 2500, {"规格": "🙂" * 2500}]}
    asyncio.run(routes._review_product_texts([("specifications", nested)], "owner"))
    assert calls == ["尺寸", "中" * 2500, "规格", "🙂" * 2500]


@pytest.mark.parametrize("length,ok", [(2499, True), (2500, True), (2501, False)])
def test_individual_text_length_boundary(length, ok, monkeypatch):
    calls = []

    async def review(text, **kwargs):
        calls.append(text)
        if len(text) > 2500:
            raise HTTPException(status_code=400, detail="too long")

    monkeypatch.setattr(routes, "require_safe_text", review)
    try:
        asyncio.run(routes._review_product_texts([("name", "x" * length)], "owner"))
        succeeded = True
    except HTTPException as exc:
        succeeded = False
        assert "name" in exc.detail
    assert succeeded is ok
    assert len(calls) == (0 if length == 2501 else 1)


def test_review_failure_stops_before_later_texts(monkeypatch):
    calls = []

    async def review(text, **kwargs):
        calls.append(text)
        if text == "unsafe":
            raise HTTPException(status_code=400, detail="blocked")

    monkeypatch.setattr(routes, "require_safe_text", review)
    with pytest.raises(HTTPException):
        asyncio.run(routes._review_product_texts([("attributes", {"name": "unsafe", "value": "later"})], "owner"))
    assert calls == ["name", "unsafe"]


def test_missing_openid_fails_closed_without_review(monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("review must not be called")

    monkeypatch.setattr(routes, "require_safe_text", forbidden)
    with pytest.raises(HTTPException) as exc:
        asyncio.run(routes._review_product_texts([("name", "title")], None))
    assert exc.value.status_code == 403

def test_sensitive_log_fields_are_redacted_and_request_id_retained():
    import logging
    from core.logging import RequestIdFilter

    record = logging.LogRecord(
        "content", logging.ERROR, __file__, 1,
        "request authorization=Bearer TOKEN-CANARY openid=OPENID-CANARY error_type=ValueError",
        (), None,
    )
    assert RequestIdFilter().filter(record)
    message = record.getMessage()
    assert "TOKEN-CANARY" not in message
    assert "OPENID-CANARY" not in message
    assert "error_type=ValueError" in message
    assert record.request_id == "-"

def test_sensitive_values_are_redacted_from_formatted_exception_and_quoted_dict(caplog):
    import logging

    from core.logging import RequestIdFilter

    logger = logging.getLogger("security.content.redaction")
    log_filter = RequestIdFilter()
    logger.addFilter(log_filter)
    try:
        with caplog.at_level(logging.ERROR, logger=logger.name):
            try:
                raise ValueError("access_token=EXCEPTION-TOKEN-CANARY")
            except ValueError as inner:
                try:
                    raise RuntimeError("wrapper") from inner
                except RuntimeError:
                    logger.exception('provider failed {"openid": "DICT-OPENID-CANARY", "password": "DICT PASSWORD CANARY"} authorization="Bearer TOKEN-CANARY"')
    finally:
        logger.removeFilter(log_filter)
    assert "EXCEPTION-TOKEN-CANARY" not in caplog.text
    assert "DICT-OPENID-CANARY" not in caplog.text
    assert "DICT-PASSWORD-CANARY" not in caplog.text
    assert "DICT PASSWORD CANARY" not in caplog.text
    assert "TOKEN-CANARY" not in caplog.text
    assert "ValueError" in caplog.text and " in test_sensitive_values_are_redacted" in caplog.text

def test_wxacode_provider_error_log_contains_no_payload_or_binary_canary():
    import io
    import logging
    import httpx
    from core.logging import RequestIdFilter
    from services import wechat_api

    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.addFilter(RequestIdFilter())
    logger = logging.getLogger(wechat_api.__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.ERROR)
    response = httpx.Response(
        200,
        headers={"content-type": "application/json"},
        content=b'{"errcode": 40001, "errmsg": "openid=WX-OPENID-CANARY"}',
    )
    try:
        with pytest.raises(ValueError):
            wechat_api._wxacode_response_to_png(response, "getwxacode")
    finally:
        logger.removeHandler(handler)
        handler.close()
    rendered = output.getvalue()
    assert "WX-OPENID-CANARY" not in rendered
    assert "40001" in rendered
    assert "getwxacode" in rendered
