# api/offline/routes.py  —— 统一风格版
from fastapi import APIRouter, HTTPException, Query, Depends, Request, Response
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

from core.database import get_conn
from core.auth import get_current_user          # 如需登录鉴权
from core.logging import get_logger
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from services.offline_service import OfflineService   # 业务逻辑层（稍后实现）
import xmltodict

logger = get_logger(__name__)
router = APIRouter()
security = HTTPBearer()
router = APIRouter(
    dependencies=[Depends(security)]  # Swagger 会识别并出现锁图标
)

# ------------------ 请求/响应模型 ------------------
class CreateOrderReq(BaseModel):
    merchant_id: int
    store_name: str
    amount: int = Field(..., gt=0)
    product_name: str = ""
    remark: str = ""


class CreateOrderRsp(BaseModel):
    order_no: str
    qrcode_url: str
    expire_at: datetime


class OrderDetailRsp(BaseModel):
    order_no: str
    amount: int
    store_name: str
    product_name: str
    status: int
    coupons: List


class RefundReq(BaseModel):
    order_no: str
    refund_amount: Optional[int] = None


# ------------------ 1. 创建支付单 ------------------
@router.post("/dingdan/chuangjian", summary="创建支付单")
async def create_offline_order(
    req: CreateOrderReq,
    current_user: dict = Depends(get_current_user)   # 如需登录
):
    try:
        result = await OfflineService.create_order(
            merchant_id=req.merchant_id,
            store_name=req.store_name,
            amount=req.amount,
            product_name=req.product_name,
            remark=req.remark,
            user_id=current_user["id"]
        )
        return {"code": 0, "message": "下单成功", "data": result}
    except Exception as e:
        logger.error(f"创建离线订单失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 2. 刷新收款码 ------------------
@router.put("/shoukuanma/shuaixin", summary="刷新收款码")
async def refresh_qrcode(
    order_no: str = Query(..., description="订单号"),
    current_user: dict = Depends(get_current_user)
):
    try:
        result = await OfflineService.refresh_qrcode(
            order_no=order_no,
            user_id=current_user["id"]
        )
        return {"code": 0, "message": "刷新成功", "data": result}
    except Exception as e:
        logger.error(f"刷新收款码失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 3. 订单详情 ------------------
@router.get("/dingdan/xiangqing/{order_no}", summary="订单详情")
async def get_order_detail(
    order_no: str,
    user_id: int = Query(..., description="用户ID"),
    current_user: dict = Depends(get_current_user)
):
    try:
        result = await OfflineService.get_order_detail(
            order_no=order_no,
            user_id=user_id
        )
        return {"code": 0, "message": "查询成功", "data": result}
    except Exception as e:
        logger.error(f"查询订单详情失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 4. 统一下单（调起支付） ------------------
@router.post("/zhifu/tongyi", summary="统一下单")
async def unified_order(
    order_no: str = Query(...),
    coupon_id: Optional[int] = Query(None),
    current_user: dict = Depends(get_current_user)
):
    try:
        result = await OfflineService.unified_order(
            order_no=order_no,
            coupon_id=coupon_id,
            user_id=current_user["id"]
        )
        return {"code": 0, "message": "下单成功", "data": result}
    except Exception as e:
        logger.error(f"统一下单失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 5. 支付回调 ------------------
@router.post("/zhifu/notify", summary="微信回调")
async def pay_notify(request: Request):
    raw_body = await request.body()          # ← 二进制
    result = await OfflineService.handle_notify(raw_body)
    return Response(content=result, media_type="application/xml")


# ------------------ 6. 订单列表 ------------------
@router.get("/dingdan/liebiao", summary="订单列表")
async def list_orders(
    merchant_id: int,
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    try:
        result = await OfflineService.list_orders(
            merchant_id=merchant_id,
            page=page,
            size=size
        )
        return {"code": 0, "message": "查询成功", "data": result}
    except Exception as e:
        logger.error(f"订单列表查询失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 7. 退款 ------------------
@router.post("/tuikuan", summary="退款")
async def refund(
    req: RefundReq,
    current_user: dict = Depends(get_current_user)
):
    try:
        result = await OfflineService.refund(
            order_no=req.order_no,
            refund_amount=req.refund_amount,
            user_id=current_user["id"]
        )
        return {"code": 0, "message": "退款受理成功", "data": result}
    except Exception as e:
        logger.error(f"退款失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 8. 收款码状态 ------------------
@router.get("/shoukuanma/zhuangtai", summary="收款码状态")
async def qrcode_status(
    order_no: str = Query(...),
    current_user: dict = Depends(get_current_user)
):
    try:
        result = await OfflineService.qrcode_status(
            order_no=order_no,
            merchant_id=current_user["id"]   # ← 传当前登录用户
        )
        return {"code": 0, "message": "查询成功", "data": result}
    except Exception as e:
        logger.error(f"收款码状态查询失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 9. 注册函数 ------------------
def register_offline_routes(app) -> None:
    app.include_router(
        router,
        prefix="/api/offline",
        tags=["线下收银台付款模块"],   # 与 main.py 里 tags_metadata 的 name 保持一致
        responses={
            400: {"description": "业务错误"},
            401: {"description": "未认证"},
            500: {"description": "服务器内部错误"}
        }
    )
    logger.info("✅ 离线支付路由注册完成 (路径: /api/offline/*)")