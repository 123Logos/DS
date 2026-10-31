"""V1.1 会员权益与白酒专区接口模型。

约定（接口文档第 10 章）：

* 权益数量一律用十进制字符串传输（`"100.000000"`），禁止用 float 表达数量；
* 金额（酒价）用整数分 `*_fen`；
* 统一信封 `{code, message, data, request_id}`，`data` 按接口展开而非任意 object。
"""
from __future__ import annotations

from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Generic, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")


def _parse_decimal(raw: str, field: str, *, positive: bool) -> str:
    """校验十进制字符串并规范化，拒绝 NaN/Infinity/科学计数法以外的非法写法。"""
    text = (raw or "").strip()
    if not text or len(text) > 40:
        raise ValueError(f"{field} 必须为长度不超过 40 的十进制字符串")
    try:
        value = Decimal(text)
    except InvalidOperation as exc:
        raise ValueError(f"{field} 不是合法数值") from exc
    if not value.is_finite():
        raise ValueError(f"{field} 不能为 NaN/Infinity")
    if positive and value <= 0:
        raise ValueError(f"{field} 必须大于 0")
    if value < 0:
        raise ValueError(f"{field} 不能为负数")
    if value.as_tuple().exponent < -6:
        raise ValueError(f"{field} 最多支持 6 位小数")
    return str(value)


class ApiEnvelope(BaseModel, Generic[T]):
    """统一返回信封。"""

    code: str = Field("OK", description="业务码，成功固定 OK")
    message: str = Field("成功", description="提示信息")
    data: Optional[T] = Field(None, description="业务数据")
    request_id: str = Field("", description="请求追踪 ID")


# ---------------- 请求模型 ----------------

class EggExchangeRequest(BaseModel):
    """优惠券兑换咯哒蛋请求。"""

    coupon_quantity: str = Field(
        ...,
        description="提交的优惠券数量，十进制字符串，必须大于 0，最多 6 位小数",
        examples=["100"],
    )
    expected_unit_value: Optional[str] = Field(
        None,
        description="前端报价时的实时咯哒值。传入后服务端校验是否被并发改价，不一致返回 409 QUOTE_STALE；不传则不校验",
        examples=["0.010000"],
    )

    @field_validator("coupon_quantity")
    @classmethod
    def _check_quantity(cls, value: str) -> str:
        return _parse_decimal(value, "coupon_quantity", positive=True)

    @field_validator("expected_unit_value")
    @classmethod
    def _check_unit_value(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return _parse_decimal(value, "expected_unit_value", positive=True)


class WineRedemptionQuoteRequest(BaseModel):
    """咯哒券兑酒报价请求。"""

    listing_id: int = Field(..., gt=0, description="白酒挂牌 ID", examples=[1])
    jars: int = Field(1, ge=1, le=6, description="兑换坛数，1-6 坛（Q8 一人限购 6 坛的保守上限）", examples=[1])


# ---------------- 返回模型 ----------------

class CapabilitiesModel(BaseModel):
    can_list_wine: bool = Field(..., description="是否具备白酒挂牌权限（六星店长）")


class PointsBalanceModel(BaseModel):
    balance: str = Field(..., description="积分余额，长期有效不清零", examples=["10000.000000"])


class RainBalanceModel(BaseModel):
    balance: str = Field(..., description="雨点余额，中间值，不可提现/不可兑换", examples=["0.000000"])


class CouponBalanceModel(BaseModel):
    balance: str = Field(..., description="优惠券余额", examples=["100.000000"])
    expiring_quantity: Optional[str] = Field(None, description="即将过期数量，窗口未确认前为 null")


class EggsModel(BaseModel):
    quantity: str = Field(..., description="持有咯哒蛋数量", examples=["8000.000000"])
    avg_cost_goda_value: Optional[str] = Field(None, description="加权平均成本咯哒值（Q4），无持仓为 null")
    current_value: Optional[str] = Field(None, description="当前权益计量值 = 数量 × 实时咯哒值，不是提现金额")
    current_unit_value: Optional[str] = Field(None, description="实时咯哒值，平台库存为 0 时为 null")
    growth_ratio: Optional[str] = Field(None, description="相对成本的增值比例，1 表示增值 100%（Q4 触发线）")
    conversion_threshold_ratio: str = Field("1.000000", description="触发线比例常量，仅用于客观规则展示")


class GodaCouponModel(BaseModel):
    balance: str = Field(..., description="咯哒券余额，只能兑换坛装白酒", examples=["160.000000"])


class RightsMeResponse(BaseModel):
    """我的权益总览。"""

    model_config = ConfigDict(from_attributes=True)

    member_level: int = Field(..., description="会员等级")
    capabilities: CapabilitiesModel
    points: PointsBalanceModel
    rain: RainBalanceModel
    coupons: CouponBalanceModel
    eggs: EggsModel
    goda_coupons: GodaCouponModel
    valuation_version: Optional[int] = Field(None, description="估值版本号")
    rule_version: str = Field(..., description="规则版本快照")
    valued_at: Optional[datetime] = Field(None, description="估值时刻")
    blocked_questions: list[str] = Field(default_factory=list, description="影响展示口径的未确认问题编号")
    disclaimer: str = Field(..., description="合规声明")


class PoolSnapshotResponse(BaseModel):
    """底池与咯哒值快照。"""

    total_supply: str = Field(..., description="咯哒蛋发行总量，恒定 1 亿，无增发入口")
    pool_coupon_balance: str = Field(..., description="底池优惠券余额")
    subsidy_coupon_balance: str = Field(..., description="雨点补贴池余额（本阶段只入不出，Q12 暂缓）")
    platform_egg_balance: str = Field(..., description="平台未发放咯哒蛋库存")
    unit_value: Optional[str] = Field(None, description="实时咯哒值 = 底池券 ÷ 平台蛋库存，库存为 0 时为 null")
    valuation_version: int = Field(..., description="估值版本号")
    valued_at: Optional[datetime] = Field(None, description="估值时刻")
    rule_version: str = Field(..., description="规则版本快照")
    blocked_questions: list[str] = Field(default_factory=list, description="未确认问题编号")
    disclaimer: str = Field(..., description="合规声明")


class AutoConversionModel(BaseModel):
    """本次兑换后顺带触发的自动转券结果。"""

    conversion_id: str = Field(..., description="转券操作号")
    egg_quantity_converted: str = Field(..., description="清零的咯哒蛋数量")
    goda_coupon_quantity: str = Field(..., description="发放的咯哒券数量")
    cost_basis: str = Field(..., description="触发时的加权平均成本咯哒值")
    unit_value: str = Field(..., description="触发时实时咯哒值")
    triggered_at: Optional[datetime] = Field(None, description="触发时间")


class EggExchangeResponse(BaseModel):
    """兑换咯哒蛋结果。"""

    exchange_id: str = Field(..., description="兑换操作号")
    status: str = Field(..., description="操作状态")
    coupon_quantity: str = Field(..., description="本次扣除的优惠券数量")
    pool_in_quantity: str = Field(..., description="入底池数量（80%）")
    subsidy_in_quantity: str = Field(..., description="入雨点补贴池数量（20%）")
    egg_quantity: str = Field(..., description="本次发放咯哒蛋数量")
    executed_unit_value: str = Field(..., description="成交咯哒值（入池前实时值，Q6）")
    unit_value_after: Optional[str] = Field(None, description="成交后实时咯哒值")
    avg_cost_goda_value: str = Field(..., description="更新后的加权平均成本咯哒值（Q4）")
    egg_quantity_total: str = Field(..., description="成交后累计持有咯哒蛋")
    coupon_balance_after: str = Field(..., description="成交后优惠券余额")
    valuation_version_before: Optional[int] = Field(None, description="成交前估值版本")
    valuation_version_after: Optional[int] = Field(None, description="成交后估值版本")
    rule_version: str = Field(..., description="规则版本快照")
    created_at: Optional[datetime] = Field(None, description="成交时间")
    idempotent_replay: bool = Field(False, description="true 表示命中幂等键，返回的是首次结果")
    auto_conversion: Optional[AutoConversionModel] = Field(None, description="若成交后立即达到 Q4 触发线，返回本次转券结果")


class WineFeesModel(BaseModel):
    packaging_fen: Optional[int] = Field(None, description="包装费（分），null 表示 Q13 未确认，不是免费")
    container_fen: Optional[int] = Field(None, description="器皿费（分），null 表示 Q13 未确认")
    shipping_fen: Optional[int] = Field(None, description="物流费（分），null 表示 Q13 未确认")


class WineRedemptionQuoteResponse(BaseModel):
    """咯哒券兑酒报价（第一阶段只报价，不落单）。"""

    quote_id: str = Field(..., description="报价单号")
    listing_id: str = Field(..., description="挂牌 ID")
    contract_no: str = Field(..., description="酒坛合同编号")
    jars: int = Field(..., description="坛数")
    weight_jin: str = Field(..., description="合计重量（斤）")
    goda_coupon_quantity: str = Field(..., description="应付咯哒券数量（3,000/坛）")
    goda_coupon_balance: str = Field(..., description="当前咯哒券余额")
    pool_coupon_debit: str = Field(..., description="底池券扣减量：Q7 明确兑酒不扣底池，恒为 0")
    wine_price_fen: int = Field(..., description="酒价（分），仅含酒价")
    fees: WineFeesModel
    rule_version: str = Field(..., description="规则版本快照")
    expires_at: Optional[datetime] = Field(None, description="报价过期时间")
    blocked_questions: list[str] = Field(default_factory=list, description="阻塞问题编号")
    disclaimer: str = Field(..., description="合规声明")
