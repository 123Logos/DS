"""V1.1 权益接口（/api/v1/rights）。

全部接口强制 Bearer 认证：用户归属取自认证身份，不接受客户端传入 user_id。
"""
from __future__ import annotations

import re
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException

from core.auth import get_current_user
from core.logging import get_logger
from core.request_context import get_request_id
from models.schemas.rights import (
    ApiEnvelope,
    EggExchangeRequest,
    EggExchangeResponse,
    PoolSnapshotResponse,
    RightsMeResponse,
)
from services.rights_service import ERR_INVALID_ARGUMENT, RightsError, RightsService

logger = get_logger(__name__)

router = APIRouter()

_IDEMPOTENCY_PATTERN = re.compile(r"^[A-Za-z0-9:_-]{8,96}$")


def _require_idempotency_key(value: Optional[str]) -> Optional[str]:
    """校验客户端幂等键格式；未传时由服务层按普通请求处理。"""
    if value is None:
        return None
    if not _IDEMPOTENCY_PATTERN.match(value):
        raise RightsError(ERR_INVALID_ARGUMENT, 422, "Idempotency-Key 需为 8-96 位字母、数字、冒号、下划线或连字符")
    return value


@router.get(
    "/rights/me",
    response_model=ApiEnvelope[RightsMeResponse],
    summary="💠 我的权益总览",
)
def get_my_rights(user: dict = Depends(get_current_user)) -> ApiEnvelope[RightsMeResponse]:
    """返回当前登录会员的积分、雨点、优惠券、咯哒蛋、咯哒券与咯哒值快照。"""
    data = RightsService().get_my_rights(int(user["id"]))
    return ApiEnvelope[RightsMeResponse](
        message="成功",
        data=RightsMeResponse(**data),
        request_id=get_request_id(),
    )


@router.get(
    "/rights/pool",
    response_model=ApiEnvelope[PoolSnapshotResponse],
    summary="🏦 底池与实时咯哒值",
)
def get_pool_snapshot(user: dict = Depends(get_current_user)) -> ApiEnvelope[PoolSnapshotResponse]:
    """平台池快照。咯哒蛋总量恒定，无任何增发接口。"""
    data = RightsService().get_pool_snapshot()
    return ApiEnvelope[PoolSnapshotResponse](
        message="成功",
        data=PoolSnapshotResponse(**data),
        request_id=get_request_id(),
    )


@router.post(
    "/rights/egg-exchanges",
    response_model=ApiEnvelope[EggExchangeResponse],
    summary="🥚 优惠券兑换咯哒蛋",
)
def create_egg_exchange(
    payload: EggExchangeRequest,
    idempotency_key: Optional[str] = Header(
        None,
        alias="Idempotency-Key",
        max_length=96,
        description="幂等键（建议必传）：同一会员同一键重复提交返回首次结果，不同参数返回 409",
    ),
    user: dict = Depends(get_current_user),
) -> ApiEnvelope[EggExchangeResponse]:
    """单事务完成：扣券 → 80% 入底池 / 20% 入雨点补贴池 → 发放咯哒蛋 → 更新加权平均成本。"""
    key = _require_idempotency_key(idempotency_key)
    data = RightsService().exchange_eggs(
        user_id=int(user["id"]),
        coupon_quantity=payload.coupon_quantity,
        expected_unit_value=payload.expected_unit_value,
        idempotency_key=key,
    )
    return ApiEnvelope[EggExchangeResponse](
        message="兑换成功",
        data=EggExchangeResponse(**data),
        request_id=get_request_id(),
    )
