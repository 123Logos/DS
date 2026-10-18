"""
微信小程序服务器消息推送（明文模式）——接收发货管理相关事件。

在微信公众平台配置服务器 URL 为本服务地址，例如：https://你的域名/wechat-wxa/msg
与微信支付回调 URL 相互独立；详见：
https://developers.weixin.qq.com/miniprogram/dev/platform-capabilities/business-capabilities/order-shipping/order-shipping.html
"""
from __future__ import annotations

import hashlib
import hmac
import json
import xml.etree.ElementTree as ET

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, PlainTextResponse

from core.config import ENVIRONMENT, settings
from core.logging import get_logger
from services.wechat_trade_manage_service import (
    process_trade_manage_order_settlement,
    process_trade_manage_remind_access_api,
    process_trade_manage_remind_shipping,
    process_wxa_trade_controlled,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/wechat-wxa", tags=["微信小程序"])


def _verify_wxa_url_signature(signature: str, timestamp: str, nonce: str, token: str) -> bool:
    if not token:
        return False
    tmp = "".join(sorted([token, str(timestamp), str(nonce)]))
    expect = hashlib.sha1(tmp.encode("utf-8")).hexdigest()
    return hmac.compare_digest(expect, signature)


def _parse_plain_xml_body(body: bytes) -> dict:
    root = ET.fromstring(body)

    def convert(node: ET.Element):
        children = list(node)
        if not children:
            return (node.text or "").strip()
        return {child.tag: convert(child) for child in children}

    return convert(root)


def _parse_wxa_message(body: bytes, content_type: str) -> dict:
    if "json" in content_type.lower() or body.lstrip().startswith(b"{"):
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("message body must be an object")
        return data
    return _parse_plain_xml_body(body)


@router.get("/msg", summary="小程序消息推送 URL 校验")
async def wxa_msg_verify(
    signature: str = Query(..., alias="signature"),
    echostr: str = Query(..., alias="echostr"),
    timestamp: str = Query(..., alias="timestamp"),
    nonce: str = Query(..., alias="nonce"),
):
    token = (settings.WECHAT_WXA_MSG_TOKEN or "").strip()
    if not token:
        if ENVIRONMENT == "production":
            raise HTTPException(status_code=503, detail="未配置 WECHAT_WXA_MSG_TOKEN")
        logger.warning("未配置 WECHAT_WXA_MSG_TOKEN，开发环境跳过签名校验并返回 echostr")
        return PlainTextResponse(content=echostr)

    if not _verify_wxa_url_signature(signature, timestamp, nonce, token):
        logger.error("小程序 URL 校验 signature 失败")
        raise HTTPException(status_code=403, detail="invalid signature")

    return PlainTextResponse(content=echostr)


@router.post("/msg", summary="小程序消息推送（发货管理等事件）")
async def wxa_msg_push(request: Request):
    token = (settings.WECHAT_WXA_MSG_TOKEN or "").strip()
    signature = request.query_params.get("signature", "")
    timestamp = request.query_params.get("timestamp", "")
    nonce = request.query_params.get("nonce", "")

    body = await request.body()
    if not body:
        return PlainTextResponse(content="success")

    if token:
        if not _verify_wxa_url_signature(signature, timestamp, nonce, token):
            logger.error("小程序消息推送 signature 校验失败")
            raise HTTPException(status_code=403, detail="invalid signature")
    elif ENVIRONMENT == "production":
        raise HTTPException(status_code=503, detail="未配置 WECHAT_WXA_MSG_TOKEN")

    try:
        data = _parse_wxa_message(body, request.headers.get("content-type", ""))
    except (ET.ParseError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as e:
        logger.error("解析小程序消息失败: %s", e)
        raise HTTPException(status_code=400, detail="invalid message") from e

    msg_type = data.get("MsgType") or data.get("msg_type") or ""
    event = data.get("Event") or data.get("event") or ""
    logger.info("小程序推送 MsgType=%s Event=%s keys=%s", msg_type, event, list(data.keys()))

    if msg_type != "event" or not event:
        return PlainTextResponse(content="success")

    if event == "wxa_media_check":
        from services.avatar_moderation_service import AvatarModerationService

        AvatarModerationService.handle_result(data)
    elif event == "trade_manage_remind_shipping":
        process_trade_manage_remind_shipping(data)
    elif event == "trade_manage_order_settlement":
        process_trade_manage_order_settlement(data)
    elif event == "trade_manage_remind_access_api":
        process_trade_manage_remind_access_api(data)
    elif event == "wxa_trade_controlled":
        process_wxa_trade_controlled(data)
    else:
        logger.info("未专门处理的小程序事件 Event=%s，已忽略", event)

    return PlainTextResponse(content="success")


@router.get(
    "/media/avatar/{media_token}",
    include_in_schema=False,
    summary="微信头像审核临时媒体访问",
)
def get_avatar_review_media(media_token: str):
    from services.avatar_moderation_service import AvatarModerationService

    media = AvatarModerationService.get_media(media_token)
    if not media:
        raise HTTPException(status_code=404, detail="media not found")
    path, media_type = media
    return FileResponse(
        path,
        media_type=media_type,
        headers={
            "Cache-Control": "no-store, max-age=0",
            "X-Content-Type-Options": "nosniff",
        },
    )


def register_wechat_wxa_routes(app):
    app.include_router(router)
