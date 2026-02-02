# models/schemas/user.py - 用户系统 Pydantic 模型
from fastapi import Query
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from core.config import UserStatus
from datetime import datetime
from typing import List




class SetStatusReq(BaseModel):
    mobile: str
    new_status: UserStatus          # 现在只能输入 0、1、2，且自动带校验/文档
    reason: str = "后台调整"


class RegisterReq(BaseModel):
    """注册请求"""
    mobile: str
    password: str
    name: Optional[str] = None
    referrer_mobile: Optional[str] = None


class LoginReq(BaseModel):
    """登录请求"""
    mobile: str
    password: str


class SetLevelReq(BaseModel):
    """设置会员等级请求"""
    mobile: str
    new_level: int = Field(ge=0, le=6)
    reason: str = "后台手动调整"



class AddressReq(BaseModel):
    mobile: str
    name: str
    phone: str
    province: str
    city: str
    district: str
    detail: str
    is_default: bool = False
    addr_type: str = "shipping"

    model_config = ConfigDict(validate_by_name=True)  # Pydantic V2: 同时支持 name / consignee_name


class UpdateAddressReq(BaseModel):
    mobile: str
    name: Optional[str] = None
    phone: Optional[str] = None
    province: Optional[str] = None
    city: Optional[str] = None
    district: Optional[str] = None
    detail: Optional[str] = None
    is_default: Optional[bool] = None
    addr_type: Optional[str] = None

    model_config = ConfigDict(validate_by_name=True)


class PointsReq(BaseModel):
    """积分请求"""
    mobile: str
    type: str = Field(pattern="^(member|merchant)$")
    amount: float = Field(..., description="积分数量（正数增加，负数减少），支持小数点后4位精度")
    reason: str = "系统赠送"


class PageQuery(BaseModel):
    """分页查询"""
    page: int = Query(1, ge=1)
    size: int = Query(10, ge=1, le=200)


class AuthReq(BaseModel):
    """认证请求"""
    mobile: str
    password: str
    name: Optional[str] = None


class AuthResp(BaseModel):
    """认证响应"""
    uid: int
    token: str
    level: int
    is_new: bool


class UserInfoResp(BaseModel):
    """用户信息响应"""
    uid: int
    mobile: str
    name: Optional[str]
    avatar_path: Optional[str]
    member_level: int
    is_merchant: int
    status: UserStatus
    referral_code: Optional[str]
    direct_count: int
    team_total: int
    assets: dict
    referrer: Optional[dict] = None


class UpdateProfileReq(BaseModel):
    """更新资料请求"""
    mobile: str
    name: Optional[str] = None
    avatar_path: Optional[str] = None
    old_password: Optional[str] = None
    new_password: Optional[str] = None


class ResetPwdReq(BaseModel):
    """重置密码请求"""
    mobile: str
    sms_code: str = Field(..., description="短信验证码（先 mock 111111）")
    new_password: str


class AdminResetPwdReq(BaseModel):
    """管理员重置密码请求"""
    mobile: str
    new_password: str
    admin_key: str = Field(..., description="后台口令")


class SelfDeleteReq(BaseModel):
    """自助注销请求"""
    mobile: str
    password: str
    reason: str = "用户自助注销"


class FreezeReq(BaseModel):
    """冻结请求"""
    mobile: str
    admin_key: str = Field(..., description="后台口令")
    reason: str = "后台冻结/解冻"


class ResetPasswordReq(BaseModel):
    """重置密码请求（别名）"""
    mobile: str
    sms_code: str
    new_password: str


class BindReferrerReq(BaseModel):
    mobile: str                       # 被推荐人手机号
    referrer_mobile: Optional[str] = None  # 推荐人手机号（老逻辑保留）
    referrer_code: Optional[str] = None    # 新增：推荐码（优先用）

class MobileResp(BaseModel):
    mobile: str

class ChangeMobileReq(BaseModel):
    user_id: int
    old_mobile: str
    new_mobile: str
    sms_code: str = Field(..., description="短信验证码（先 mock 111111）")


class ChangeMobileReq(BaseModel):
    user_id: int
    old_mobile: str
    new_mobile: str

class AvatarUploadResp(BaseModel):
    avatar_urls: List[str]          # ← 与商品图一样返回数组
    uploaded_at: datetime


class CouponInfo(BaseModel):
    """优惠券详情模型"""
    id: int
    coupon_type: str
    amount: float = Field(..., description="优惠券金额")
    status: str
    valid_from: str = Field(..., description="有效期开始日期(YYYY-MM-DD)")
    valid_to: str = Field(..., description="有效期结束日期(YYYY-MM-DD)")
    used_at: Optional[str] = Field(None, description="使用时间")
    created_at: str = Field(..., description="发放时间")
    order_no: Optional[str] = Field(None, description="关联订单号（如果有）")

class CouponStats(BaseModel):
    """优惠券统计信息"""
    total_count: int
    unused_count: int
    used_count: int
    expired_count: int
    total_amount: float
    unused_amount: float


class UnilevelStatusResponse(BaseModel):
    """联创状态响应"""
    current_level: int = Field(..., description="当前联创等级（0=未获得）")
    target_level: int = Field(..., description="应得等级")
    can_promote: bool = Field(..., description="是否可以自动晋升")
    reason: Optional[str] = Field(None, description="不可晋升原因")

class UnilevelPromoteResponse(BaseModel):
    """联创晋升响应"""
    new_level: int = Field(..., description="晋升后的等级")
    message: str = Field(..., description="提示信息")
'''
class UserSpecialPointsResponse(BaseModel):
    """团队和推荐点数查询响应"""
    team_reward_points: float = Field(..., description="团队奖励专用点数", example=89.1234)
    referral_points: float = Field(..., description="推荐奖励专用点数", example=45.6789)
class UserSubsidyPointsResponse(BaseModel):
    """周补贴专用点数查询响应"""
    subsidy_points: float = Field(..., description="周补贴专用点数", example=1234.5678)

class UserUnilevelPointsResponse(BaseModel):
    """联创星级专用点数查询响应"""
    unilevel_points: float = Field(..., description="联创星级专用点数", example=9876.5432)
'''
class UserAllPointsResponse(BaseModel):
    """用户所有点数查询响应"""
    unilevel_points: float = Field(..., description="联创星级专用点数", example=9876.5432)
    subsidy_points: float = Field(..., description="周补贴专用点数", example=1234.5678)
    team_reward_points: float = Field(..., description="团队奖励专用点数", example=89.1234)
    referral_points: float = Field(..., description="推荐奖励专用点数", example=45.6789)
    total_points: float = Field(..., description="四个点数总和", example=11245.9133)
'''
class ClearRewardPointsReq(BaseModel):
    """清除奖励点数请求"""
    user_id: int = Field(..., description="用户ID", gt=0)
    admin_key: str = Field(..., description="后台口令")
    reason: str = Field("后台清除", description="操作原因")

class ClearSubsidyPointsReq(BaseModel):
    """清除周补贴点数请求"""
    user_id: int = Field(..., description="用户ID", gt=0)
    admin_key: str = Field(..., description="后台口令")
    reason: str = Field("后台清除", description="操作原因")

class ClearUnilevelPointsReq(BaseModel):
    """清除联创星级点数请求"""
    user_id: int = Field(..., description="用户ID", gt=0)
    admin_key: str = Field(..., description="后台口令")
    reason: str = Field("后台清除", description="操作原因")
'''

class UserPointsSummaryResponse(BaseModel):
    """用户点数汇总查询响应"""
    # 四个获取渠道（累计获得）
    unilevel_points: float = Field(..., description="联创星级-累计获得", example=10000.00)
    subsidy_points: float = Field(..., description="周补贴-累计获得", example=5000.00)
    team_reward_points: float = Field(..., description="团队奖励-累计获得", example=2000.00)
    referral_points: float = Field(..., description="推荐奖励-累计获得", example=1000.00)

    # 汇总数据
    cumulative_total: float = Field(..., description="累计总值（四个渠道之和）", example=18000.00)
    remaining_points: float = Field(..., description="剩余点数（true_total_points）", example=11000.00)
    used_points: float = Field(..., description="已使用点数", example=7000.00)

class SetUnilevelReq(BaseModel):
    """后台设置联创星级请求"""
    user_id: int = Field(..., gt=0, description="用户ID")
    level: int = Field(..., ge=0, le=3, description="联创等级：0=无, 1=一星, 2=二星, 3=三星")
    admin_key: str = Field(..., description="后台口令")


class ReferralQRResponse(BaseModel):
    """推荐码二维码响应模型"""
    qr_url: Optional[str] = None
    message: str = "success"

    class Config:
        from_attributes = True  # 兼容 ORM 模式


# =============== 手机号解密模型（芝士老版本） ===============

class DecryptPhoneReq(BaseModel):
    """手机号解密请求"""
    code: str              # 微信登录凭证
    encrypted_data: str    # getPhoneNumber 返回的加密数据
    iv: str               # 解密向量


class DecryptPhoneResp(BaseModel):
    """手机号解密响应"""
    phone: str            # 解密后的手机号
    message: str = "success"

# =============== 手机号快速验证模型(这是super ultra extra new type) ===============

class GetPhoneReq(BaseModel):
    """手机号快速验证请求"""
    code: str  # 微信返回的手机号凭证
    user_id: int  # ✅ 添加用户ID字段

class GetPhoneResp(BaseModel):
    """手机号快速验证响应"""
    phone: str  # 明文手机号
    message: str = "success"