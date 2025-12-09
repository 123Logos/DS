# models/schemas/order.py - 订单系统 Pydantic 模型
from pydantic import BaseModel, Field
from typing import Optional


class CartAdd(BaseModel):
    """购物车添加商品模型"""
    user_id: int
    product_id: int
    quantity: int = Field(default=1, ge=1)


class OrderCreate(BaseModel):
    """创建订单模型"""
    user_id: int
    address_id: Optional[int] = None
    custom_address: Optional[dict] = None


class OrderPay(BaseModel):
    """订单支付模型"""
    order_number: str
    pay_way: str


class StatusUpdate(BaseModel):
    """订单状态更新模型"""
    order_number: str
    new_status: str
    reason: Optional[str] = None


class RefundApply(BaseModel):
    """退款申请模型"""
    order_number: str
    refund_type: str
    reason_code: str


class RefundAudit(BaseModel):
    """退款审核模型"""
    order_number: str
    approve: bool
    reject_reason: Optional[str] = None


# 商家相关模型
class MShip(BaseModel):
    """商家发货模型"""
    order_number: str


class MRefundAudit(BaseModel):
    """商家退款审核模型"""
    order_number: str
    approve: bool
    reject_reason: Optional[str] = None


class MBindBank(BaseModel):
    """绑定银行卡模型"""
    bank_name: str
    bank_account: str


class MWithdraw(BaseModel):
    """商家提现模型"""
    amount: float = Field(..., gt=0)
