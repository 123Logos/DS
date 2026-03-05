# api/offline/routes.py  —— 统一风格版
from fastapi import APIRouter, HTTPException, Query, Depends, Request, Response, Body
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from typing import Union
from core.database import get_conn
from core.auth import get_current_user          # 如需登录鉴权
from core.logging import get_logger
from core.config import settings
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from services.offline_service import OfflineService   # 业务逻辑层（稍后实现）
import xmltodict
from services.notify_service import handle_pay_notify
from decimal import Decimal, ROUND_HALF_UP
from services.finance_service import FinanceService

logger = get_logger(__name__)
security = HTTPBearer()
router = APIRouter(
    dependencies=[Depends(security)]  # Swagger 会识别并出现锁图标
)

# ------------------ 请求/响应模型 ------------------
class CreateOrderReq(BaseModel):
    merchant_id: int
    store_name: str
    amount: float = Field(..., gt=0, description="订单金额（单位：元），后端会自动转成分")
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


# ------------------ 0. 微信支付配置检查 ------------------
@router.get("/zhifu/config-check", summary="检查微信支付配置状态")
async def check_wechat_pay_config(
        current_user: dict = Depends(get_current_user)
):
    """
    检查当前微信支付配置状态，用于排查支付问题
    """
    config_status = {
        "wx_mock_mode": settings.WX_MOCK_MODE,
        "app_id_configured": bool(settings.WECHAT_APP_ID),
        "mch_id_configured": bool(settings.WECHAT_PAY_MCH_ID),
        "api_v3_key_configured": bool(settings.WECHAT_PAY_API_V3_KEY) and len(settings.WECHAT_PAY_API_V3_KEY) > 0,
        "cert_path_configured": bool(settings.WECHAT_PAY_API_CERT_PATH),
        "key_path_configured": bool(settings.WECHAT_PAY_API_KEY_PATH),
        "pub_key_id_configured": bool(settings.WECHAT_PAY_PUB_KEY_ID),
        "notify_url_configured": bool(settings.WECHAT_PAY_NOTIFY_URL),
    }

    # 检查证书文件是否存在
    import os
    if settings.WECHAT_PAY_API_CERT_PATH:
        config_status["cert_file_exists"] = os.path.exists(settings.WECHAT_PAY_API_CERT_PATH)
    if settings.WECHAT_PAY_API_KEY_PATH:
        config_status["key_file_exists"] = os.path.exists(settings.WECHAT_PAY_API_KEY_PATH)
    if settings.WECHAT_PAY_PUBLIC_KEY_PATH:
        config_status["pub_key_file_exists"] = os.path.exists(settings.WECHAT_PAY_PUBLIC_KEY_PATH)

    # 判断整体状态
    is_fully_configured = (
            not settings.wx_mock_mode_bool and  # ✅ 使用布尔属性
            config_status["app_id_configured"] and
            config_status["mch_id_configured"] and
            config_status["api_v3_key_configured"] and
            config_status.get("cert_file_exists", False) and
            config_status.get("key_file_exists", False)
    )

    config_status["is_fully_configured"] = is_fully_configured

    if settings.wx_mock_mode_bool:   # ✅ 使用布尔属性
        config_status["warning"] = "当前处于 Mock 模式，支付将使用模拟数据，不会真正扣款"
    elif not is_fully_configured:
        config_status["warning"] = "微信支付配置不完整，可能导致支付失败"
    else:
        config_status["message"] = "微信支付配置正常"

    return {"code": 0, "message": "查询成功", "data": config_status}


class UnifiedOrderBody(BaseModel):
    """统一下单请求体，前端会传 openid、user_id、total_fee（单位：分）"""
    openid: Optional[str] = None
    user_id: Optional[int] = None
    total_fee: Optional[int] = Field(None, description="支付金额单位：分，用于调微信统一下单")


# ------------------ 1. 创建支付单 ------------------
@router.post("/dingdan/chuangjian", summary="创建支付单")
async def create_offline_order(
    req: CreateOrderReq,
    current_user: dict = Depends(get_current_user)
):
    try:
        # ✅ 把前端传的「元」转为「分」（int）
        amount_fen: int = int(
            (Decimal(str(req.amount)) * 100).quantize(Decimal('1'), rounding=ROUND_HALF_UP)
        )

        if amount_fen <= 0:
            raise ValueError("订单金额必须大于 0 元")

        # ✅ 关键修复：传入 amount_fen（单位：分）
        result = await OfflineService.create_order(
            merchant_id=req.merchant_id,
            store_name=req.store_name,
            amount=amount_fen,                    # ← 改这里！
            product_name=req.product_name,
            remark=req.remark,
            user_id=current_user["id"]
        )
        return {"code": 0, "message": "下单成功", "data": result}

    except ValueError as e:   # 业务校验错误
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"创建离线订单失败: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))

# ==================== 新增：生成永久收款码 ====================
@router.post("/permanent-qrcode", summary="生成商户永久收款码")
async def generate_permanent_qrcode(
    merchant_id: int = Query(..., description="商家ID"),
    current_user: dict = Depends(get_current_user)
):
    """
    为商家生成长期有效的小程序码，扫码后进入可输入金额、使用优惠券的支付页面。
    仅商家本人或管理员可操作。
    """
    # 权限校验：只能操作自己的商户ID，或管理员
    if current_user["id"] != merchant_id and not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="无权操作此商户的收款码")

    try:
        # 调用服务层生成二维码
        result = await OfflineService.generate_permanent_qrcode(
            merchant_id=merchant_id
        )
        return {"code": 0, "message": "生成成功", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"生成永久收款码失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
# ==============================================================

# ==================== 新增：用户创建订单（永久码场景） ====================
@router.post("/order/create", summary="用户创建订单（永久码场景）")
async def create_order_for_user(
    merchant_id: int = Query(..., description="商家ID"),
    amount: int = Query(..., gt=0, description="订单金额（单位：分）"),
    coupon_id: Optional[int] = Query(None, description="优惠券ID（可选）"),
    current_user: dict = Depends(get_current_user)
):
    """
    用户输入金额后调用此接口创建订单，返回订单号。
    此接口不生成二维码，用于永久码扫码后的支付流程。
    """
    try:
        order_no = await OfflineService.create_order_for_user(
            merchant_id=merchant_id,
            user_id=current_user["id"],
            amount=amount,
            coupon_id=coupon_id
        )
        return {"code": 0, "message": "订单创建成功", "data": {"order_no": order_no}}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"创建订单失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="服务器内部错误")
# ==============================================================

# ==================== 新增：获取当前用户可用优惠券 ====================
@router.get("/coupons", summary="获取当前用户可用优惠券")
async def list_available_coupons(
    amount: Optional[int] = Query(None, gt=0, description="订单金额（分），用于过滤门槛（可选）"),
    current_user: dict = Depends(get_current_user)
):
    """
    返回用户当前可用的优惠券列表，可传入订单金额用于过滤门槛（如有）。
    """
    try:
        svc = FinanceService()
        coupons = svc.list_available(user_id=current_user["id"], amount=amount or 0)
        return {"code": 0, "message": "查询成功", "data": coupons}
    except Exception as e:
        logger.error(f"查询优惠券失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="查询失败")
# ==============================================================

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
@router.post("/zhifu/tongyi", summary="统一下单（支持优惠券）")
async def unified_order(
    order_no: str = Query(..., description="订单号"),
    coupon_id: Optional[int] = Query(None, description="优惠券ID（可选）"),
    total_fee_query: Optional[int] = Query(None, alias="total_fee", description="支付金额单位：分（可选，与 body 二选一）"),
    current_user: dict = Depends(get_current_user),
    body: Optional[UnifiedOrderBody] = Body(None),
):
    openid = current_user.get("openid")
    if not openid and body and body.openid:
        openid = body.openid
    if not openid:
        logger.error(f"用户 {current_user['id']} 未绑定微信 openid")
        raise HTTPException(status_code=400, detail="用户未绑定微信，无法支付")

    # 从 body 或 query 取 total_fee（单位：分），供后端调微信统一下单使用
    total_fee = None
    if body and body.total_fee is not None and body.total_fee > 0:
        total_fee = body.total_fee
    elif total_fee_query is not None and total_fee_query > 0:
        total_fee = total_fee_query

    # 记录日志，方便排查
    logger.info(f"[unified_order] 订单={order_no}, 用户={current_user['id']}, "
                f"coupon_id={coupon_id}, total_fee={total_fee}, "
                f"mock_mode={settings.WX_MOCK_MODE}")

    try:
        result = await OfflineService.unified_order(
            order_no=order_no,
            coupon_id=coupon_id,
            user_id=current_user["id"],
            openid=openid,
            total_fee=total_fee,
        )

        # 检查返回的支付参数
        pay_params = result.get("pay_params", {})
        if not pay_params.get("paySign"):
            logger.error(f"[unified_order] 支付参数缺少 paySign: {pay_params}")
            raise HTTPException(status_code=500, detail="支付参数生成失败，缺少签名")

        # 如果是 Mock 模式，添加警告信息
        if settings.wx_mock_mode_bool:   # ✅ 使用布尔属性
            result["warning"] = "当前处于 Mock 模式，支付不会真正扣款"
            result["is_mock"] = True
        else:
            result["is_mock"] = False

        return {
            "code": 0,
            "message": "统一下单成功",
            "data": {
                "order_no": order_no,
                "wechat_pay_params": result["pay_params"],
                "amount_info": {
                    "original_amount": result["original_amount"],
                    "coupon_discount": result["coupon_discount"],
                    "final_amount": result["final_amount"]
                },
                "is_mock": result.get("is_mock", False),
                "warning": result.get("warning")
            }
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"统一下单失败: {e}", exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 5. 支付回调 ------------------
@router.post("/zhifu/notify", summary="微信回调")
async def pay_notify(request: Request):
    raw_body = await request.body()
    # 唯一变动：把原来 OfflineService.handle_notify 换成新的 handle_pay_notify
    result = await handle_pay_notify(raw_body)
    return Response(content=result, media_type="application/xml")


# ------------------ 6. 订单列表 ------------------
@router.get("/dingdan/liebiao", summary="订单列表（支持买方或卖方查询）")
async def list_orders(
    merchant_id: Optional[int] = Query(None, description="商家ID（卖方）"),
    user_id: Optional[int] = Query(None, description="用户ID（买方）"),
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=200),
    current_user: dict = Depends(get_current_user)
):
    # 参数校验：必须传 merchant_id 或 user_id 其中一个
    if not merchant_id and not user_id:
        raise HTTPException(status_code=400, detail="请传入 merchant_id 或 user_id 其中一个参数")
    if merchant_id and user_id:
        raise HTTPException(status_code=400, detail="merchant_id 和 user_id 不能同时传入")

    try:
        result = await OfflineService.list_orders(
            merchant_id=merchant_id,
            user_id=user_id,
            page=page,
            size=size
        )
        return {"code": 0, "message": "查询成功", "data": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
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