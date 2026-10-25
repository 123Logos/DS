# api/offline/routes.py  —— 统一风格版
import json

from fastapi import APIRouter, HTTPException, Query, Depends, Request, Response, Body
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime
from typing import Union
from core.database import get_conn
from core.auth import get_current_user, is_platform_admin, require_platform_admin
from core.logging import get_logger
from core.config import settings
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from services.offline_service import OfflineService   # 业务逻辑层（稍后实现）
import xmltodict
from decimal import Decimal, ROUND_HALF_UP
from services.finance_service import FinanceService
from core.rate_limiter import pay_bridge_ip_limiter
from services.wechat_api import (
    get_or_create_permanent_pay_openlink,
    get_or_create_permanent_pay_urllink,
)

logger = get_logger(__name__)
security = HTTPBearer()
# 扫码落地页无需 Bearer（与静态页 /offline/ 配合）
offline_public_router = APIRouter()
pay_bridge_router = APIRouter()


def _pay_bridge_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _pay_bridge_is_wechat_browser(request: Request) -> bool:
    ua = (request.headers.get("user-agent") or "").lower()
    return "micromessenger" in ua

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
        current_user: dict = Depends(require_platform_admin)
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
    coupon_id: Optional[int] = Field(None, description="单张优惠券ID（兼容旧客户端）")
    coupon_ids: Optional[List[int]] = Field(None, description="多张优惠券ID（叠加抵扣）")


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

        # 检查金额范围
        if amount_fen <= 0:
            raise ValueError("订单金额必须大于 0 元")
        if amount_fen > 1000000000:  # 1000万分 = 10万元上限
            raise ValueError("订单金额不能超过 10 万元")

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
        logger.error('offline_order_create_failed')
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
        logger.error('offline_qrcode_create_failed')
        raise HTTPException(status_code=500, detail=str(e))
# ==============================================================

# ==================== 新增：用户创建订单（永久码场景） ====================
@router.post("/order/create", summary="用户创建订单（永久码场景）")
async def create_order_for_user(
    merchant_id: int = Query(..., description="商家ID"),
    amount: int = Query(..., gt=0, description="订单金额（单位：分）"),
    coupon_id: Optional[int] = Query(None, description="优惠券ID（可选，兼容单券）"),
    coupon_ids: Optional[str] = Query(
        None,
        description="多张优惠券ID，逗号分隔（例如：1,2,3）；与 coupon_id 可同时存在，后端会去重合并",
    ),
    current_user: dict = Depends(get_current_user)
):
    """
    用户输入金额后调用此接口创建订单，返回订单号。
    此接口不生成二维码，用于永久码扫码后的支付流程。
    """
    try:
        parsed_ids: Optional[List[int]] = None
        if coupon_ids:
            try:
                parsed_ids = [int(x.strip()) for x in coupon_ids.split(",") if x.strip()]
            except ValueError:
                raise HTTPException(status_code=400, detail="coupon_ids 格式错误，应为逗号分隔整数")

        order_no = await OfflineService.create_order_for_user(
            merchant_id=merchant_id,
            user_id=current_user["id"],
            amount=amount,
            coupon_id=coupon_id,
            coupon_ids=parsed_ids,
        )
        return {"code": 0, "message": "订单创建成功", "data": {"order_no": order_no}}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error('offline_buyer_order_failed')
        raise HTTPException(status_code=500, detail="服务器内部错误")
# ==============================================================

# ==================== 永久收款 H5 中转（普通二维码请指向此 URL） ====================
# 须在 main.py 中于 app.mount("/offline", StaticFiles...) 之前注册 pay_bridge_router，
# 否则 /offline 会被静态目录或占位路由抢先匹配。
@pay_bridge_router.get("/offline", include_in_schema=False)
@pay_bridge_router.get("/pay-bridge", include_in_schema=False)
async def offline_h5_pay_landing(
    request: Request,
    pay_id: int = Query(..., alias="id", ge=1, le=2_147_483_647, description="商户用户 ID"),
):
    """
    普通二维码统一为 https://<域名>/offline?id=<商户用户ID>。
    /pay-bridge?id= 为兼容旧码，与 /offline 行为相同。
    服务端调用微信 generate_urllink / generatescheme 拉起小程序页 pages/offline/permanentPay?id=...
    """
    from urllib.parse import quote

    ip = _pay_bridge_client_ip(request)
    if not pay_bridge_ip_limiter.allow(ip):
        logger.warning('offline_bridge_rate_limited')
        return HTMLResponse(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"/><title>访问过快</title></head>"
            "<body><p>访问过于频繁，请稍后再试。</p></body></html>",
            status_code=429,
        )

    if not OfflineService.is_valid_offline_permanent_pay_target(pay_id):
        logger.info("[offline-pay] 无效或未授权商户 ip=%s id=%s", ip, pay_id)
        return HTMLResponse(
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"/><title>无效链接</title></head>"
            "<body><p>收款链接无效或已失效。</p></body></html>",
            status_code=404,
        )

    logger.info("[offline-pay] 有效请求 ip=%s id=%s", ip, pay_id)

    path_enc = quote(f"pages/offline/permanentPay?id={pay_id}", safe="")
    fallback = (
        f"https://servicewechat.com/{settings.WECHAT_APP_ID}/0/page-frame.html?path={path_enc}"
    )

    if settings.wx_mock_mode_bool or not (settings.WECHAT_APP_ID and settings.WECHAT_APP_SECRET):
        logger.debug("[offline-pay] Mock 或未配置密钥，使用 servicewechat 回退 id=%s", pay_id)
        return RedirectResponse(fallback, status_code=302)

    # 微信内置浏览器：用加密 URL Scheme 在页面内立即 replace，通常比 302 到 URL Link 少一层「确认打开」中间页
    if _pay_bridge_is_wechat_browser(request):
        try:
            openlink = await get_or_create_permanent_pay_openlink(pay_id)
            safe = json.dumps(openlink, ensure_ascii=False)
            html = (
                "<!DOCTYPE html><html><head><meta charset=\"utf-8\"/>"
                "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"/>"
                "<title>正在打开小程序</title>"
                f"<script>location.replace({safe});</script>"
                "</head><body><p>正在打开小程序…</p></body></html>"
            )
            return HTMLResponse(html)
        except Exception as e:
            logger.warning('offline_scheme_unavailable')

    try:
        link = await get_or_create_permanent_pay_urllink(pay_id)
        return RedirectResponse(link, status_code=302)
    except Exception as e:
        logger.warning('offline_url_link_unavailable')
        return RedirectResponse(fallback, status_code=302)


# ==================== 普通二维码跳转页（兼容旧链接 / 无 url_link 场景） ====================
@offline_public_router.get("/permanentPay", include_in_schema=False)
async def offline_permanent_pay(
    merchant_id: Optional[int] = Query(None, description="商家用户 ID（旧链接）"),
    pay_id: Optional[int] = Query(None, alias="id", description="商家用户 ID"),
):
    """
    兼容旧版二维码：https://<your-domain>/api/offline/permanentPay?merchant_id=123
    新普通二维码请使用 /offline?id=123（见 generate_permanent_qrcode 返回的 universal_link）。
    """
    from urllib.parse import quote

    if pay_id is not None:
        mid = pay_id
        path = quote(f"pages/offline/permanentPay?id={mid}", safe="")
    elif merchant_id is not None:
        mid = merchant_id
        path = quote(f"pages/offline/permanentPay?merchant_id={mid}", safe="")
    else:
        raise HTTPException(status_code=400, detail="缺少参数 id 或 merchant_id")

    appid = settings.WECHAT_APP_ID
    url = f"https://servicewechat.com/{appid}/0/page-frame.html?path={path}"
    return RedirectResponse(url)


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
        logger.error('offline_coupon_query_failed')
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
        logger.error('offline_qrcode_refresh_failed')
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
        logger.error('offline_order_query_failed')
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 4. 统一下单（调起支付） ------------------
@router.post("/zhifu/tongyi", summary="统一下单（支持优惠券）")
async def unified_order(
    order_no: str = Query(..., description="订单号"),
    coupon_id_query: Optional[str] = Query(
        None,
        alias="coupon_id",
        description="优惠券ID（可选）。支持单张整数，或与前端一致的多张逗号分隔（如 328,327），等价于 coupon_ids",
    ),
    coupon_ids_query: Optional[str] = Query(
        None,
        alias="coupon_ids",
        description="多张优惠券ID，逗号分隔（例如：1,2,3）；也可使用 JSON Body 传 coupon_ids 数组",
    ),
    total_fee_query: Optional[int] = Query(None, alias="total_fee", description="支付金额单位：分（可选，与 body 二选一）"),
    current_user: dict = Depends(get_current_user),
    body: Optional[UnifiedOrderBody] = Body(None),
):
    openid = current_user.get("openid")
    if body and body.openid and body.openid != openid:
        raise HTTPException(403, '支付身份不匹配')
    if not openid:
        logger.error(f"用户 {current_user['id']} 未绑定微信 openid")
        raise HTTPException(status_code=400, detail="用户未绑定微信，无法支付")

    # 从 body 或 query 取 total_fee（单位：分），供后端调微信统一下单使用
    total_fee = None
    if body and body.total_fee is not None and body.total_fee > 0:
        total_fee = body.total_fee
    elif total_fee_query is not None and total_fee_query > 0:
        total_fee = total_fee_query

    merged_coupon_ids: Optional[List[int]] = None
    if body and body.coupon_ids:
        merged_coupon_ids = list(body.coupon_ids)
    if coupon_ids_query:
        try:
            q_ids = [int(x.strip()) for x in coupon_ids_query.split(",") if x.strip()]
        except ValueError:
            raise HTTPException(status_code=400, detail="coupon_ids 格式错误，应为逗号分隔整数")
        merged_coupon_ids = (merged_coupon_ids or []) + q_ids

    # coupon_id 查询参数兼容：单整数 或 逗号分隔多张（避免前端误传导致 422）
    merged_coupon_id: Optional[int] = None
    if coupon_id_query is not None and str(coupon_id_query).strip():
        raw = str(coupon_id_query).strip()
        if "," in raw:
            try:
                from_coupon_id = [int(x.strip()) for x in raw.split(",") if x.strip()]
            except ValueError:
                raise HTTPException(status_code=400, detail="coupon_id 格式错误，应为整数或逗号分隔整数")
            merged_coupon_ids = (merged_coupon_ids or []) + from_coupon_id
        else:
            try:
                merged_coupon_id = int(raw)
            except ValueError:
                raise HTTPException(status_code=400, detail="coupon_id 格式错误，应为整数")

    if body and body.coupon_id is not None:
        # body 里的单券与 query 冲突时，优先使用 body（更贴近 POST JSON 语义）
        merged_coupon_id = body.coupon_id

    # 记录日志，方便排查
    logger.info(f"[unified_order] 订单={order_no}, 用户={current_user['id']}, "
                f"coupon_id={merged_coupon_id}, coupon_ids={merged_coupon_ids}, total_fee={total_fee}, "
                f"mock_mode={settings.WX_MOCK_MODE}")

    try:
        result = await OfflineService.unified_order(
            order_no=order_no,
            coupon_id=merged_coupon_id,
            user_id=current_user["id"],
            openid=openid,
            total_fee=total_fee,
            coupon_ids=merged_coupon_ids,
        )

        # 检查返回的支付参数
        pay_params = result.get("pay_params", {})
        if not pay_params.get("paySign"):
            logger.error('offline_payment_missing_signature')
            raise HTTPException(status_code=500, detail="支付参数生成失败，缺少签名")

        # 如果是 Mock 模式，添加警告信息
        if settings.wx_mock_mode_bool:   # ✅ 使用布尔属性
            result["warning"] = "当前处于 Mock 模式，支付不会真正扣款"
            result["is_mock"] = True
        else:
            result["is_mock"] = False

        tw = result.get("merchant_transfer_warning")
        resp_warning = result.get("warning")
        if tw:
            resp_warning = f"{resp_warning + '；' if resp_warning else ''}商家微信转账失败（已记账，请修证书/商户配置）: {tw}"

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
                "warning": resp_warning,
                "merchant_transfer_warning": tw,
            }
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error('offline_payment_failed')
        raise HTTPException(503, '支付暂时不可用') from None


# ------------------ 5. 支付回调 ------------------
@offline_public_router.post('/zhifu/notify', summary='微信回调')
async def pay_notify(request: Request):
    from api.wechat_pay.routes import wechat_pay_notify
    return await wechat_pay_notify(request)


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
    target_id = merchant_id if merchant_id is not None else user_id
    if not is_platform_admin(current_user) and int(target_id) != int(current_user['id']):
        raise HTTPException(403, '无权查询其他账号订单')

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
        logger.error('offline_order_list_failed')
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
    except HTTPException:
        raise
    except Exception:
        logger.error('offline_refund_failed')
        raise HTTPException(503, '退款未完成，请使用原退款号恢复') from None


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
        logger.error('offline_qrcode_status_failed')
        raise HTTPException(status_code=400, detail=str(e))


# ------------------ 9. 注册函数 ------------------
def register_offline_routes(app) -> None:
    shared = {
        "tags": ["线下收银台付款模块"],
        "responses": {
            400: {"description": "业务错误"},
            401: {"description": "未认证"},
            500: {"description": "服务器内部错误"},
        },
    }
    # pay_bridge_router（/offline、/pay-bridge）在 main.py 中于 mount /offline 静态目录之前注册
    app.include_router(offline_public_router, prefix="/api/offline", tags=shared["tags"])
    app.include_router(router, prefix="/api/offline", **shared)
    logger.info("✅ 离线支付路由注册完成 (路径: /api/offline/*)")