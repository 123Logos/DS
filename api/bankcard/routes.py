# api/bankcard/routes.py
from fastapi import APIRouter, HTTPException, Depends, Request, Header, Query, Form
from typing import Optional, List
from pydantic import BaseModel, Field, validator
import re

from services.bankcard_service import BankcardService
from core.logging import get_logger
from core.auth import get_current_user

logger = get_logger(__name__)
router = APIRouter()


class BankcardBindRequest(BaseModel):
    """银行卡绑定请求（对齐微信字段）"""
    account_name: str = Field(..., min_length=2, max_length=100, description="开户名称")
    account_number: str = Field(..., min_length=16, max_length=30, description="银行卡号")
    account_bank: str = Field(..., min_length=2, max_length=50, description="开户银行")
    bank_name: str = Field(..., min_length=2, max_length=128, description="开户行全称（含支行）")
    bank_branch_id: Optional[str] = Field(None, max_length=128, description="开户行联行号")
    bank_address_code: str = Field(..., pattern=r'^\d{6}$', description="开户地区码(6位数字)")
    sms_code: str = Field(..., description="短信验证码")

    @validator('account_number')
    def validate_account_number(cls, v):
        if not re.match(r'^\d+$', v):
            raise ValueError("银行卡号必须为数字")
        return v

    class Config:
        schema_extra = {
            "example": {
                "account_name": "张三",
                "account_number": "6222021234567890000",
                "account_bank": "工商银行",
                "bank_name": "中国工商银行股份有限公司北京朝阳支行",
                "bank_branch_id": "402713354941",
                "bank_address_code": "110105",
                "sms_code": "123456"
            }
        }


class BankcardModifyRequest(BaseModel):
    """银行卡改绑请求"""
    new_account_name: str = Field(..., min_length=2, max_length=100, description="新开户名称")
    new_account_number: str = Field(..., min_length=16, max_length=30, description="新银行卡号")
    new_account_bank: str = Field(..., min_length=2, max_length=50, description="新开户银行")
    new_bank_name: str = Field(..., min_length=2, max_length=128, description="新开户行全称")
    bank_branch_id: Optional[str] = Field(None, max_length=128, description="新开户行联行号")
    bank_address_code: Optional[str] = Field(None, pattern=r'^\d{6}$', description="新开户地区码")
    sms_code: str = Field(..., description="短信验证码")

    @validator('new_account_number')
    def validate_account_number(cls, v):
        if not re.match(r'^\d+$', v):
            raise ValueError("银行卡号必须为数字")
        return v

    class Config:
        schema_extra = {
            "example": {
                "new_account_name": "李四",
                "new_account_number": "6222029876543210000",
                "new_account_bank": "建设银行",
                "new_bank_name": "中国建设银行股份有限公司北京海淀支行",
                "bank_branch_id": "105100000021",
                "bank_address_code": "110108",
                "sms_code": "123456"
            }
        }


# ============= API路由（保持不变） =============

@router.post("/bind", summary="绑定银行卡", tags=["银行卡管理"])
async def bind_bankcard(
    request: BankcardBindRequest,
    current_user: dict = Depends(get_current_user)
):
    """绑定银行卡（需先完成微信进件，自动同步微信数据）"""
    try:
        result = BankcardService.bind_bankcard(
            user_id=current_user["id"],
            bank_name=request.account_bank,
            bank_account=request.account_number,
            account_name=request.account_name,
            bank_branch_id=request.bank_branch_id,
            bank_address_code=request.bank_address_code,
            is_default=True,  # 首次绑定设为默认
            admin_key=None,
            ip_address="127.0.0.1"
        )
        return {"code": 0, "message": "绑定成功", "data": result}
    except Exception as e:
        logger.error(f"绑定失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/sms/send", summary="发送短信验证码（测试环境返回模拟验证码）", tags=["银行卡管理"])
async def send_sms_code(
    account_number: str = Form(..., description="银行卡号"),
    current_user: dict = Depends(get_current_user)
):
    """发送短信验证码（Mock模式返回固定验证码123456）"""
    try:
        result = await BankcardService.send_sms_code(
            user_id=current_user["id"],
            account_number=account_number
        )
        return {"code": 0, "message": "验证码已发送", "data": result}
    except Exception as e:
        logger.error(f"发送验证码失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/modify/apply", summary="申请改绑银行卡", tags=["银行卡管理"])
async def apply_modify_bankcard(
    request: BankcardModifyRequest,
    current_user: dict = Depends(get_current_user)
):
    """申请改绑银行卡（需验证微信数据，原卡自动解绑）"""
    try:
        result = BankcardService.modify_bankcard(
            user_id=current_user["id"],
            new_bank_name=request.new_account_bank,
            new_bank_account=request.new_account_number,
            new_account_name=request.new_account_name,
            bank_branch_id=request.bank_branch_id,
            bank_address_code=request.bank_address_code,
            admin_key=None,
            ip_address="127.0.0.1"
        )
        return {"code": 0, "message": "改绑申请已提交", "data": result}
    except Exception as e:
        logger.error(f"改绑申请失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/modify/status", summary="查询改绑审核状态", tags=["银行卡管理"])
async def get_modify_status(
    application_no: str = Query(..., description="申请单号"),
    current_user: dict = Depends(get_current_user)
):
    """查询改绑申请审核状态（自动同步微信最新状态）"""
    try:
        result = BankcardService.poll_modify_status(
            user_id=current_user["id"],
            application_no=application_no
        )
        return {"code": 0, "message": "查询成功", "data": result}
    except Exception as e:
        logger.error(f"查询改绑状态失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/list", summary="获取银行卡列表", tags=["银行卡管理"])
async def list_bankcards(
    current_user: dict = Depends(get_current_user)
):
    """查询已绑定的银行卡列表（脱敏，不包含完整卡号）"""
    try:
        result = BankcardService.list_bankcards(user_id=current_user["id"])
        return {"code": 0, "message": "查询成功", "data": result}
    except Exception as e:
        logger.error(f"查询列表失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/status", summary="查询绑定状态", tags=["银行卡管理"])
async def get_bind_status(
    current_user: dict = Depends(get_current_user)
):
    """查询用户银行卡绑定状态（包含微信同步信息）"""
    try:
        result = BankcardService.query_bind_status(user_id=current_user["id"])
        return {"code": 0, "message": "查询成功", "data": result}
    except Exception as e:
        logger.error(f"查询状态失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/logs", summary="获取操作日志", tags=["银行卡管理"])
async def get_logs(
    limit: int = Query(50, ge=1, le=1000, description="返回条数"),
    current_user: dict = Depends(get_current_user)
):
    """获取银行卡操作日志列表（脱敏）"""
    try:
        result = BankcardService.get_operation_logs(
            user_id=current_user["id"],
            limit=limit
        )
        return {"code": 0, "message": "查询成功", "data": result}
    except Exception as e:
        logger.error(f"获取日志失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/my", summary="查询我的银行卡（明文）", tags=["银行卡管理"])
async def get_my_bankcard(
    current_user: dict = Depends(get_current_user)
):
    """查询当前用户的银行卡完整信息（前端需脱敏展示）"""
    try:
        result = BankcardService.query_my_bankcard(user_id=current_user["id"])
        return {"code": 0, "message": "查询成功", "data": result}
    except Exception as e:
        logger.error(f"查询我的银行卡失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/default/set", summary="设置默认银行卡", tags=["银行卡管理"])
async def set_default_bankcard(
    account_id: int = Form(..., description="银行卡ID"),
    current_user: dict = Depends(get_current_user)
):
    """设置默认结算账户（原子操作）"""
    try:
        result = BankcardService.set_default_bankcard(
            user_id=current_user["id"],
            account_id=account_id
        )
        return {"code": 0, "message": "设置成功", "data": result}
    except Exception as e:
        logger.error(f"设置默认卡失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ========== 路由注册函数（保持不变） ==========

def register_bankcard_routes(app):
    """注册银行卡路由"""
    app.include_router(
        router,
        prefix="/api/bankcard",
        tags=["银行卡管理"],
        responses={
            400: {"description": "业务错误"},
            401: {"description": "未认证"},
            500: {"description": "服务器内部错误"}
        }
    )
    logger.info("✅ 银行卡路由注册完成 (路径: /api/bankcard/*)")