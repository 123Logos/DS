from fastapi import (
    APIRouter, Depends, HTTPException,
    UploadFile, File, Query, Form, FastAPI
)
from typing import Optional

from core.logging import get_logger
from core.exceptions import FinanceException
from models.schemas.store_setup import *
from services.store_setup_service import StoreSetupService, StoreAdminService

logger = get_logger(__name__)

router = APIRouter(prefix="/api/store", tags=["店铺设置"])


def get_store_service() -> StoreSetupService:
    return StoreSetupService()


def get_admin_service() -> StoreAdminService:
    return StoreAdminService()


# ==================== 用户端接口 ====================

@router.post(
    "/info/create",
    response_model=dict,
    summary="创建店铺信息",
    description="支付进件成功后，创建店铺基础信息（名称、LOGO、联系人等）"
)
async def create_store_info(
        req: StoreInfoCreateReq,
        service: StoreSetupService = Depends(get_store_service)
):
    """创建店铺信息（支付进件成功后调用）"""
    try:
        return service.create_store_info(req)
    except FinanceException as e:
        detail = str(e)
        if detail == "用户不存在" or detail.startswith("用户不存在: user_id="):
            raise HTTPException(status_code=404, detail="用户不存在")
        if detail == "请先完成支付进件，开通开店权限":
            raise HTTPException(status_code=400, detail=detail)
        if detail == "店铺信息已存在，请使用更新接口":
            raise HTTPException(status_code=409, detail=detail)
        raise HTTPException(status_code=400, detail="无法创建店铺信息")
    except Exception as e:
        logger.error("Create store info failed: error_type=%s", type(e).__name__)
        raise HTTPException(status_code=500, detail="系统错误，请稍后重试")


@router.put(
    "/info/update",
    response_model=dict,
    summary="更新店铺信息",
    description="修改已创建的店铺信息（名称、LOGO、联系方式等）"
)
async def update_store_info(
        req: StoreInfoUpdateReq,
        user_id: int = Query(..., description="用户ID"),
        service: StoreSetupService = Depends(get_store_service)
):
    """更新店铺信息"""
    try:
        return service.update_store_info(user_id, req)
    except FinanceException as e:
        if str(e) == "店铺信息不存在":
            raise HTTPException(status_code=404, detail="店铺信息不存在")
        raise HTTPException(status_code=400, detail="无法更新店铺信息")
    except Exception as e:
        logger.error("Update store info failed: error_type=%s", type(e).__name__)
        raise HTTPException(status_code=500, detail="系统错误，请稍后重试")


@router.get(
    "/info",
    response_model=Optional[StoreInfoResp],
    summary="获取店铺信息",
    description="查询当前用户的店铺详细信息"
)
async def get_store_info(
        user_id: int = Query(..., description="用户ID"),
        service: StoreSetupService = Depends(get_store_service)
):
    """获取店铺信息"""
    try:
        data = service.get_store_info(user_id)
        if data:
            return StoreInfoResp(**data)
        return None
    except Exception as e:
        logger.error("Get store info failed: error_type=%s", type(e).__name__)
        raise HTTPException(status_code=500, detail="系统错误，请稍后重试")


@router.get(
    "/setup-status",
    response_model=StoreSetupStatusResp,
    summary="获取店铺设置状态",
    description="查询用户是否具备开店权限、是否已设置店铺信息"
)
async def get_setup_status(
        user_id: int = Query(..., description="用户ID"),
        service: StoreSetupService = Depends(get_store_service)
):
    """获取店铺设置状态"""
    try:
        data = service.get_setup_status(user_id)
        return StoreSetupStatusResp(**data)
    except Exception as e:
        logger.error("Get store setup status failed: error_type=%s", type(e).__name__)
        raise HTTPException(status_code=500, detail="系统错误，请稍后重试")


@router.post(
    "/logo/upload",
    response_model=StoreLogoUploadResp,
    summary="上传店铺LOGO",
    description="上传店铺LOGO图片（最大5MB），自动压缩优化"
)
async def upload_store_logo(
    user_id: int = Form(..., description="用户ID"),
    file: UploadFile = File(..., description="LOGO图片文件"),
    service: StoreSetupService = Depends(get_store_service)
):
    """上传店铺LOGO"""
    try:
        return service.upload_store_logo(user_id, file)
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error("Upload store logo failed: error_type=%s", type(e).__name__)
        raise HTTPException(status_code=500, detail="系统错误，请稍后重试")


@router.delete(
    "/logo/delete",
    summary="删除店铺LOGO",
    description="删除当前店铺的LOGO图片"
)
async def delete_store_logo(
    user_id: int = Query(..., description="用户ID"),
    service: StoreSetupService = Depends(get_store_service)
):
    """删除店铺LOGO"""
    try:
        service.delete_store_logo(user_id)
        return {"success": True, "message": "LOGO删除成功"}
    except Exception as e:
        logger.error("Delete store logo failed: error_type=%s", type(e).__name__)
        raise HTTPException(status_code=500, detail="系统错误，请稍后重试")


@router.get(
    "/logo/preview/{image_id}",
    summary="预览LOGO",
    description="根据图片ID预览店铺LOGO"
)
async def preview_logo(
        image_id: str,
        service: StoreSetupService = Depends(get_store_service)
):
    """预览LOGO"""
    try:
        file_path = service.get_logo_url(image_id)
        if not file_path:
            raise HTTPException(status_code=404, detail="LOGO不存在")

        from fastapi.responses import FileResponse
        return FileResponse(file_path)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Preview store logo failed: error_type=%s", type(e).__name__)
        raise HTTPException(status_code=500, detail="系统错误，请稍后重试")


# ==================== 管理后台接口 ====================

@router.get(
    "/admin/list",
    response_model=dict,
    summary="获取店铺列表",
    description="管理后台分页查询所有店铺信息"
)
async def get_store_list(
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(10, ge=1, le=100, description="每页条数"),
        admin_service: StoreAdminService = Depends(get_admin_service)
):
    """获取店铺列表（管理后台）"""
    try:
        return admin_service.get_store_list(page, page_size)
    except Exception as e:
        logger.error("Get store list failed: error_type=%s", type(e).__name__)
        raise HTTPException(status_code=500, detail="系统错误，请稍后重试")


# ==================== 路由注册函数 ====================

def register_store_routes(app: FastAPI):
    """注册店铺设置路由"""
    app.include_router(router)
    logger.info("店铺设置路由已注册")