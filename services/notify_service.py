# services/notify_service.py
from __future__ import annotations
from typing import TYPE_CHECKING, Union

import pymysql  # 补充 Union
import asyncio  # 添加导入

if TYPE_CHECKING:
    from wechatpayv3 import WeChatPay
    from core.config import Settings

# 下面是你原来的 import 列表
import httpx
from decimal import Decimal
from datetime import datetime
from pathlib import Path
from core.config import settings
from core.logging import get_logger
from core.database import get_conn
from core.config import POINTS_DISCOUNT_RATE
from services.finance_service import parse_pending_coupon_ids, parse_offline_coupon_ids, max_coupon_total_yuan
from services.wechat_api import get_access_token as _wechat_stable_access_token
from cryptography import x509
from cryptography.hazmat.backends import default_backend
# 给全局变量加类型标注（仅静态检查用）
wxpay: WeChatPay | None
settings: Settings

logger = get_logger(__name__)

def _load_cert_serial_no(cert_path: str) -> str:
    try:
        path = Path(cert_path)
        if not path.exists():
            raise FileNotFoundError(f"微信支付证书文件不存在: {path}")
        with path.open("rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), backend=default_backend())
        serial = format(cert.serial_number, "x").upper()
        logger.info(f"[WeChat] loaded merchant cert serial_no from {path}: {serial}")
        return serial
    except Exception as exc:
        logger.warning(f"[WeChat] unable to load cert serial_no: {exc}")
        return ""


# ----------- 全局 wxpay 实例 ----------
if not settings.wx_mock_mode_bool:  # ✅ 修改为布尔属性
    from wechatpayv3 import WeChatPay, WeChatPayType

    # 加载商户私钥（字符串）
    _private_key = Path(settings.WECHAT_PAY_API_KEY_PATH).read_text(encoding="utf-8")

    # 加载微信支付平台公钥（字符串，不是对象！）
    public_key_str = None
    if settings.WECHAT_PAY_PUBLIC_KEY_PATH and Path(settings.WECHAT_PAY_PUBLIC_KEY_PATH).exists():
        public_key_str = Path(settings.WECHAT_PAY_PUBLIC_KEY_PATH).read_text(encoding="utf-8")

    cert_serial_no = settings.WECHAT_CERT_SERIAL_NO
    if not cert_serial_no and settings.WECHAT_PAY_API_CERT_PATH:
        cert_serial_no = _load_cert_serial_no(settings.WECHAT_PAY_API_CERT_PATH)

    if not cert_serial_no:
        raise RuntimeError("微信支付证书序列号未配置或读取失败，请检查 WECHAT_CERT_SERIAL_NO 和 WECHAT_PAY_API_CERT_PATH")

    # 初始化微信支付客户端
    wxpay = WeChatPay(
        wechatpay_type=WeChatPayType.MINIPROG,
        mchid=settings.WECHAT_PAY_MCH_ID,
        private_key=_private_key,
        cert_serial_no=cert_serial_no,
        apiv3_key=settings.WECHAT_PAY_API_V3_KEY,
        appid=settings.WECHAT_APP_ID,
        public_key=public_key_str,  # 传入字符串，不是对象
        public_key_id=settings.WECHAT_PAY_PUB_KEY_ID,
        # user_agent="github.com/wechatpay-apiv3/wechatpay-python"
    )
else:
    wxpay = None


# 2. 给用户微信“零钱到账”通知
async def _transfer_to_user(openid: str, amount: Decimal, desc: str) -> str:
    if settings.wx_mock_mode_bool:
        logger.info('mock_merchant_transfer')
        return "mock_batch_id"

    if amount <= 0:
        logger.info(f"[Notify] 转账金额为0，跳过")
        return "zero_amount"

    amount_int = int(amount * 100)
    req = {
        "appid": settings.WECHAT_APP_ID,
        "out_batch_no": f"MER{int(datetime.now().timestamp())}",
        "batch_name": "线下收银到账",
        "batch_remark": desc,
        "total_amount": amount_int,
        "total_num": 1,
        "transfer_detail_list": [{
            "out_detail_no": f"USER{int(datetime.now().timestamp())}",
            "transfer_amount": amount_int,
            "transfer_remark": desc,
            "openid": openid
        }]
    }
    try:
        # 将同步的 transfer_batch 调用放到线程池中执行
        status_code, resp_data = await asyncio.to_thread(wxpay.transfer_batch, **req)
        if status_code == 200:
            logger.info('merchant_transfer_accepted')
            return resp_data.get("batch_id", "")
        else:
            logger.error('merchant_transfer_rejected')
            raise RuntimeError('Merchant transfer rejected')
    except Exception as e:
        logger.error('merchant_transfer_failed')
        raise


# 3. 给商户微信下发「模板消息」
async def _notify_template(openid: str, order_no: str, amount: Decimal):
    if settings.wx_mock_mode_bool:  # ✅ 使用布尔属性
        logger.info('mock_merchant_notification')
        return
    """
    公众号模板消息 / 小程序订阅消息
    以公众号为例，模板 ID 需提前在后台配置
    """
    data = {
        "touser": openid,
        "template_id": settings.WECHAT_TMPL_MERCHANT_INCOME,
        "url": f"{settings.HOST}/merchant/statement",
        "data": {
            "first": {"value": "您有一笔新收款", "color": "#173177"},
            "keyword1": {"value": order_no, "color": "#173177"},
            "keyword2": {"value": f"¥{amount:.2f}", "color": "#173177"},
            "keyword3": {"value": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "color": "#173177"},
            "remark": {"value": "款项已转入您的微信零钱，请查收", "color": "#173177"}
        }
    }
    url = f"https://api.weixin.qq.com/cgi-bin/message/template/send?access_token={await _get_access_token()}"
    async with httpx.AsyncClient() as client:
        r = await client.post(url, json=data)
        r.raise_for_status()
        if r.json().get('errcode') != 0:
            raise RuntimeError('Merchant notification provider rejected delivery')
        logger.info('merchant_notification_sent')


# 4. 与 wechat_api 共用稳定版 access_token，避免与其它模块各拉各的 token 触发 40001
async def _get_access_token() -> str:
    return await _wechat_stable_access_token()


# 5. 对外唯一入口：微信到账通知
async def notify_merchant(merchant_id: int, order_no: str, amount: int) -> None:
    """
    到账推送 = 真正转账到商户微信零钱 + 下发模板消息
    amount: 单位分
    """
    amount_dec = Decimal(amount) / 100
    logger.info(f"[Notify] 商家{merchant_id} 订单{order_no} 到账{amount_dec:.2f}元")

    # 查商户 openid（需提前在 users 表保存）
    with get_conn() as conn:
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("SELECT openid FROM users WHERE id=%s", (merchant_id,))
            row = cur.fetchone()
            if not row or not row["openid"]:
                logger.warning(f"商家{merchant_id} 未绑定微信 openid，跳过微信到账")
                return

    openid = row["openid"]
    # 1. 真正转账
    await _transfer_to_user(openid, amount_dec, f"线下订单{order_no}收款")
    # 2. 模板消息
    await _notify_template(openid, order_no, amount_dec)




# 兼容调用：异步统一下单包装（服务内其他模块可能调用 ns.wxpay.async_unified_order）
async def async_unified_order(req: dict) -> dict:
    """
    异步包装：在后台线程调用 core.wx_pay_client.wxpay_client.create_jsapi_order
    目的：兼容原来期望 ns.wxpay.async_unified_order 的调用方式
    """
    if settings.wx_mock_mode_bool:  # ✅ 修改为布尔属性
        import uuid, time
        return {"prepay_id": f"MOCK_PREPAY_{int(time.time())}_{uuid.uuid4().hex[:8]}"}

    from core.wx_pay_client import wxpay_client
    out_trade_no = req.get('out_trade_no')

    # ✅ 关键修复：支持多种金额参数格式
    # 格式1: 直接传 total_fee (分)
    # 格式2: 传 amount.total (微信支付V3标准格式)
    total_fee = req.get('total_fee')
    if total_fee is None:
        amount = req.get('amount', {})
        if isinstance(amount, dict):
            total_fee = amount.get('total')

    # 确保是整数（分）
    try:
        total_fee = int(total_fee) if total_fee else 0
    except (ValueError, TypeError):
        raise ValueError(f"无效的金额参数: {total_fee}")

    if total_fee <= 0:
        raise ValueError(f"支付金额必须大于0: {total_fee}")

    # 提取 openid
    payer = req.get('payer', {})
    openid = payer.get('openid', '') if isinstance(payer, dict) else req.get('openid', '')

    import anyio

    def _sync_call():
        try:
            return wxpay_client.create_jsapi_order(
                out_trade_no=str(out_trade_no),
                total_fee=total_fee,  # ✅ 正确传递 total_fee
                openid=str(openid),
                description=req.get('description', '商品支付')
            )
        except Exception as e:
            # 如果底层是 requests.HTTPError，尝试提取 response 内容以便上层返回友好错误
            try:
                import requests
                if isinstance(e, requests.exceptions.HTTPError) and hasattr(e, 'response'):
                    resp = e.response
                    body = ''
                    try:
                        body = resp.text
                    except Exception:
                        body = str(resp)
                    raise RuntimeError(
                        f"WeChat create_jsapi_order failed: status={getattr(resp, 'status_code', '')} body={body}")
            except Exception:
                pass
            raise

    return await anyio.to_thread.run_sync(_sync_call)
