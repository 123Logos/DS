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
from pydantic import BaseModel, Field

from core.auth import get_current_user
from core.logging import get_logger
from services.wechat_api import msg_sec_check

logger = get_logger(__name__)

router = APIRouter()


class MsgSecCheckReq(BaseModel):
    content: str = Field(..., min_length=1, max_length=2500, description="待检测文本内容")
    scene: int = Field(1, ge=1, le=4, description="场景值：1=资料,2=评论,3=论坛,4=社交日志")
    openid: Optional[str] = Field(None, description="用户 openid（不传则使用当前登录用户的 openid）")


@router.post("/msg-sec-check", summary="内容安全检测（msgSecCheck）")
async def msg_sec_check_endpoint(
    body: MsgSecCheckReq,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """检测文本是否违规；违规时返回 pass=false，前端据此提示用户。"""
    content = body.content.strip()
    if not content:
        return {"pass": True, "message": "内容为空"}

    # 优先使用请求中的 openid，否则使用当前登录用户的 openid
    openid = (body.openid or "").strip() or (user or {}).get("openid") or ""

    try:
        result = await msg_sec_check(content, scene=body.scene, openid=openid)
    except Exception as e:
        logger.error("内容安全检测失败，降级放行: %s", e, exc_info=True)
        return {"pass": True, "message": "检测服务不可用"}

    errcode = int(result.get("errcode") or 0)
    errmsg = result.get("errmsg") or ""

    if errcode == 0:
        return {"pass": True, "message": "内容合规"}
    if errcode == 87014:
        logger.info("内容安全检测命中违规: scene=%s errmsg=%s", body.scene, errmsg)
        return {"pass": False, "message": "内容含有违规信息，请修改后重试"}

    # 其他错误码（如参数错误、频控等）：记录日志并降级放行，避免阻塞正常业务
    logger.error("内容安全检测返回异常 errcode=%s errmsg=%s", errcode, errmsg)
    return {"pass": True, "message": "检测服务异常，降级放行"}


def register_security_routes(app) -> None:
    app.include_router(router, prefix="/api/security", tags=["微信小程序"])
