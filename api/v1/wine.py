"""V1.1 白酒专区接口（/api/v1/wine）。

第一阶段只提供咯哒券兑酒报价；下单、支付、卖家结算依赖 Q9/Q10/Q13/Q15/Q16，未开放。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends

from core.auth import get_current_user
from core.request_context import get_request_id
from models.schemas.rights import (
    ApiEnvelope,
    WineRedemptionQuoteRequest,
    WineRedemptionQuoteResponse,
)
from services.rights_service import RightsService

router = APIRouter()


@router.post(
    "/wine/redemption-quotes",
    response_model=ApiEnvelope[WineRedemptionQuoteResponse],
    summary="🍶 咯哒券兑酒报价",
)
def create_wine_redemption_quote(
    payload: WineRedemptionQuoteRequest,
    user: dict = Depends(get_current_user),
) -> ApiEnvelope[WineRedemptionQuoteResponse]:
    """按 3,000 咯哒券/坛报价。

    Q7：兑酒只扣买家咯哒券，**不扣底池券**（`pool_coupon_debit` 恒为 0）；
    Q13 未确认，器皿/包装/物流三项费用返回 null（null 不等于免费）；
    报价不锁库存、不扣券，有效期见 `expires_at`。
    """
    data = RightsService().quote_wine_redemption(
        user_id=int(user["id"]),
        listing_id=payload.listing_id,
        jars=payload.jars,
    )
    return ApiEnvelope[WineRedemptionQuoteResponse](
        message="报价成功",
        data=WineRedemptionQuoteResponse(**data),
        request_id=get_request_id(),
    )
