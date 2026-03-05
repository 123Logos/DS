# services/wechat_api.py
import httpx
import base64
from core.config import settings
from core.logging import get_logger  # ✅ 新增：导入 logger

logger = get_logger(__name__)        # ✅ 新增：初始化 logger

async def get_access_token() -> str:
    """简易 access_token 缓存，7000s"""
    import time
    now = int(time.time())
    if not hasattr(get_access_token, "_cache") or now - get_access_token._cache[1] > 7000:
        url = ("https://api.weixin.qq.com/cgi-bin/token"
               "?grant_type=client_credential"
               f"&appid={settings.WECHAT_APP_ID}"
               f"&secret={settings.WECHAT_APP_SECRET}")
        async with httpx.AsyncClient() as cli:
            ret = await cli.get(url)
            ret.raise_for_status()
            get_access_token._cache = (ret.json()["access_token"], now)
    return get_access_token._cache[0]

async def get_wxacode(path: str, scene: str = "", width: int = 280) -> bytes:
    """获取临时小程序码二进制"""
    token = await get_access_token()
    url = f"https://api.weixin.qq.com/wxa/getwxacode?access_token={token}"
    body = {"path": path, "scene": scene, "width": width}
    async with httpx.AsyncClient() as cli:
        r = await cli.post(url, json=body)
        r.raise_for_status()
        return r.content

# ==================== 永久小程序码接口 ====================
async def get_wxacode_unlimit(scene: str, page: str, width: int = 280) -> bytes:
    """
    获取长期有效的小程序码（无限数量）
    :param scene: 场景值，长度不超过32个字符（如 "m=123"）
    :param page: 小程序页面路径，必须以 '/' 开头
    :param width: 二维码宽度
    :return: 图片二进制数据
    """
    token = await get_access_token()
    url = f"https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token={token}"
    payload = {
        "scene": scene,
        "page": page,
        "width": width,
        "check_path": False,          # 不校验页面是否存在（便于未发布页面）
        "env_version": "release"      # 线上版本
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, json=payload, timeout=10)
        content_type = resp.headers.get("content-type", "")
        if "image" in content_type:
            return resp.content
        else:
            error = resp.json()
            logger.error(f"生成永久小程序码失败: {error}")
            raise ValueError(error.get("errmsg", "生成失败"))