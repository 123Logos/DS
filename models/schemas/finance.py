# models/schemas/finance.py - 财务系统 Pydantic 模型
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict, Any


class ResponseModel(BaseModel):
    """通用响应模型"""
    success: bool
    message: str
    data: Optional[Dict[str, Any]] = None


class UserCreateRequest(BaseModel):
    """创建用户请求模型"""
    mobile: str = Field(..., min_length=11, max_length=11, pattern=r"^1[3-9]\d{9}$")
    name: str = Field(..., min_length=2, max_length=50)
    referrer_id: Optional[int] = None

    @field_validator('referrer_id')
    @classmethod
    def validate_referrer_id(cls, v):
        if v is not None and v < 0:
            raise ValueError("推荐人ID必须为非负整数")
        return v


class ProductCreateRequest(BaseModel):
    """创建商品请求模型（财务系统）"""
    name: str = Field(..., min_length=2, max_length=255)
    price: float = Field(..., gt=0)
    stock: int = Field(..., ge=0)
    is_member_product: int = Field(..., ge=0, le=1)
    merchant_id: int = Field(..., ge=0)


class OrderRequest(BaseModel):
    """订单请求模型"""
    order_no: str
    user_id: int = Field(..., gt=0)
    product_id: int = Field(..., gt=0)
    quantity: int = Field(1, ge=1, le=100)
    points_to_use: int = Field(0, ge=0)


class WithdrawalRequest(BaseModel):
    """提现请求模型"""
    user_id: int = Field(..., gt=0)
    amount: float = Field(..., gt=0, le=100000)
    withdrawal_type: str = Field('user', pattern=r'^(user|merchant)$')


class WithdrawalAuditRequest(BaseModel):
    """提现审核请求模型"""
    withdrawal_id: int = Field(..., gt=0)
    approve: bool
    auditor: str = Field('admin', min_length=1)


class RewardAuditRequest(BaseModel):
    """奖励审核请求模型"""
    reward_ids: List[int] = Field(..., min_length=1)
    approve: bool
    auditor: str = Field('admin', min_length=1)


class CouponUseRequest(BaseModel):
    """优惠券使用请求模型"""
    user_id: int = Field(..., gt=0)
    coupon_id: int = Field(..., gt=0)
    order_amount: float = Field(..., gt=0)


class RefundRequest(BaseModel):
    """退款请求模型"""
    order_no: str
