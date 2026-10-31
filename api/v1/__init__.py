"""V1.1 权益域路由注册入口。

新老物理隔离：本包只依赖 services.rights_service / services.settlement_service，
不导入、不修改 services/finance* 与旧 /api 路由。
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from api.v1.rights import router as rights_router
from api.v1.wine import router as wine_router
from core.logging import get_logger
from core.request_context import get_request_id
from services.rights_service import RightsError

logger = get_logger(__name__)

V1_TAG_RIGHTS = "会员权益"
V1_TAG_WINE = "白酒专区"


async def rights_error_handler(request: Request, exc: RightsError) -> JSONResponse:
    """业务异常统一返回 {code, message, data, request_id}。"""
    logger.info("rights_error code=%s path=%s", exc.code, request.url.path)
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "code": exc.code,
            "message": exc.message,
            "data": None,
            "request_id": get_request_id(),
        },
    )


def register_v1_routes(app: FastAPI) -> None:
    """注册 /api/v1 权益与白酒路由（全部强制 Bearer 认证）。"""
    app.add_exception_handler(RightsError, rights_error_handler)
    app.include_router(rights_router, prefix="/api/v1", tags=[V1_TAG_RIGHTS])
    app.include_router(wine_router, prefix="/api/v1", tags=[V1_TAG_WINE])
