"""
内容安全检测接口 —— 代理微信 msgSecCheck，供小程序发布场景调用。

对应前端 utils/security.js 的 checkContentSecurity / quickCheck，
调用路径：POST /api/security/msg-sec-check。

违规时返回 HTTP 200 + {"pass": false}（而非非 200 状态码），
这样前端 request.js 会正常 resolve，再由 security.js 依据 pass 字段拦截并提示用户。
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator

from core.auth import get_current_user
from services.wechat_api import check_text_security

router = APIRouter()


class MsgSecCheckReq(BaseModel):
    content: str = Field(..., min_length=1, max_length=2500, description="待检测文本内容")
    scene: int = Field(1, strict=True, ge=1, le=4, description="场景值：1=资料,2=评论,3=论坛,4=社交日志")
    openid: Optional[str] = Field(None, max_length=128, description="可省略；如提供，必须等于登录用户 openid，不能指定他人身份")

    @field_validator("content")
    @classmethod
    def nonblank_content(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("内容不能为空白")
        return value


class MsgSecCheckResp(BaseModel):
    passed: bool = Field(alias="pass", description="仅明确合规时为 true；false 时禁止提交")
    message: str = Field(description="用户提示，不包含微信原始响应或敏感信息")


@router.post("/msg-sec-check", response_model=MsgSecCheckResp, summary="内容安全检测（msgSecCheck）")
async def msg_sec_check_endpoint(
    body: MsgSecCheckReq,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """保留 HTTP 200 业务拦截契约；异常不能成为发布许可。"""
    openid = user.get("openid") or ""
    if not openid:
        return {"pass": False, "message": "请先登录微信小程序后重试"}
    if body.openid is not None and body.openid != openid:
        return {"pass": False, "message": "openid 与当前登录用户不匹配"}
    decision = await check_text_security(body.content, scene=body.scene, openid=openid)
    messages = {
        "pass": "内容合规",
        "risky": "内容含有违规信息，请修改后重试",
        "review": "内容需进一步审核，暂不可提交",
        "unavailable": "检测服务暂不可用，请稍后重试",
    }
    return {"pass": decision == "pass", "message": messages[decision]}


def register_security_routes(app) -> None:
    app.include_router(router, prefix="/api/security", tags=["微信小程序"])
