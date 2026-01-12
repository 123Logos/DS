# notify_service.py
import httpx
from decimal import Decimal
from datetime import datetime
from pathlib import Path
from core.config import settings
from wechatpayv3 import WeChatPay, WeChatPayType
from core.logging import get_logger

logger = get_logger(__name__)

# ----------- 全局 wxpay 实例 ----------
if not settings.WX_MOCK_MODE:
    _private_key = Path(settings.WECHAT_PAY_API_KEY_PATH).read_text(encoding="utf-8")
    wxpay = WeChatPay(
        wechatpay_type=WeChatPayType.MINIPROG,
        mchid=settings.WECHAT_PAY_MCH_ID,
        private_key=_private_key,
        cert_serial_no=settings.WECHAT_CERT_SERIAL_NO,
        api_v3_key=settings.WECHAT_PAY_API_V3_KEY,
        appid=settings.WECHAT_APP_ID,
        user_agent="github.com/wechatpay-apiv3/wechatpay-python"
    )
else:
    wxpay = None


# 2. 给用户微信“零钱到账”通知
async def _transfer_to_user(openid: str, amount: Decimal, desc: str) -> str:
    if settings.WX_MOCK_MODE:
        logger.info(f"[MOCK] 转账 {amount:.2f} 元至 {openid}（描述：{desc}）")
        return "mock_batch_id"
    amount_int = int(amount * 100)
    """
    调用微信「商家转账到零钱」
    返回微信官方订单号（可用于查询）
    """
    # 微信单位：分
    amount_int = int(amount * 100)
    req = {
        "appid": settings.WECHAT_APPID,
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
        resp = await wxpay.async_transfer_batch(req)
        logger.info(f"[WeChat] 转账成功: {resp}")
        return resp.get("batch_id", "")
    except Exception as e:
        logger.error(f"[WeChat] 转账失败: {e}")
        raise

# 3. 给商户微信下发「模板消息」
async def _notify_template(openid: str, order_no: str, amount: Decimal):
    if settings.WX_MOCK_MODE:
        logger.info(f"[MOCK] 模板消息：openid={openid} 订单={order_no} 金额={amount:.2f}")
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
        logger.info(f"[WeChat] 模板消息发送成功: {r.json()}")

# 4. 获取公众号/小程序 access_token（缓存 7000s）
async def _get_access_token() -> str:
    # 简单内存缓存，生产环境可换 Redis
    import time
    now = int(time.time())
    if not hasattr(_get_access_token, "_cache") or now - _get_access_token._cache[1] > 7000:
        url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={settings.WECHAT_APPID}&secret={settings.WECHAT_SECRET}"
        async with httpx.AsyncClient() as client:
            r = await client.get(url)
            r.raise_for_status()
            token = r.json()["access_token"]
            _get_access_token._cache = (token, now)
    return _get_access_token._cache[0]

# 5. 对外唯一入口：微信到账通知
async def notify_merchant(merchant_id: int, order_no: str, amount: int) -> None:
    """
    到账推送 = 真正转账到商户微信零钱 + 下发模板消息
    amount: 单位分
    """
    amount_dec = Decimal(amount) / 100
    logger.info(f"[Notify] 商家{merchant_id} 订单{order_no} 到账{amount_dec:.2f}元")

    # 查商户 openid（需提前在 users 表保存）
    async with get_conn() as conn:
        async with conn.cursor() as cur:
            await cur.execute("SELECT openid FROM users WHERE id=%s", (merchant_id,))
            row = await cur.fetchone()
            if not row or not row["openid"]:
                logger.warning(f"商家{merchant_id} 未绑定微信 openid，跳过微信到账")
                return

    openid = row["openid"]
    # 1. 真正转账
    await _transfer_to_user(openid, amount_dec, f"线下订单{order_no}收款")
    # 2. 模板消息
    await _notify_template(openid, order_no, amount_dec)