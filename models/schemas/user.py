# models/schemas/user.py - 用户系统 Pydantic 模型
from fastapi import Query
from pydantic import BaseModel, Field
from typing import Optional
from core.config import UserStatus


class SetStatusReq(BaseModel):
    """设置用户状态请求"""
    mobile: str
    new_status: UserStatus = Field(..., description="0-正常 1-冻结 2-注销")
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
    """地址请求"""
    mobile: str
    name: str
    phone: str
    province: str
    city: str
    district: str
    detail: str
    is_default: bool = False
    addr_type: str = "shipping"


class PointsReq(BaseModel):
    """积分请求"""
    mobile: str
    points_type: str = Field(pattern="^(member|merchant)$")
    amount: int
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
