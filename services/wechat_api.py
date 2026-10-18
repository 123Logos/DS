# services/wechat_api.py
import asyncio
import json
import time
import threading
import httpx
from core.config import settings
from core.logging import get_logger  # ✅ 新增：导入 logger

logger = get_logger(__name__)        # ✅ 新增：初始化 logger

_access_token_lock = asyncio.Lock()

_WXA_ENV_ALLOWED = frozenset({"release", "trial", "develop"})


def _normalize_wxa_env_version() -> str:
    v = (getattr(settings, "WECHAT_WXA_ENV_VERSION", None) or "release").strip().lower()
    return v if v in _WXA_ENV_ALLOWED else "release"


def _looks_like_stale_access_token(msg: str) -> bool:
    t = msg.lower()
    return "invalid credential" in t or "not latest" in t


def _wxacode_response_to_png(resp: httpx.Response, context: str) -> bytes:
    """微信接口失败时常返回 JSON；成功为 PNG/JPEG 二进制。避免把 JSON 当图片保存。"""
    raw = resp.content
    if len(raw) >= 8 and raw[:8] == b"\x89PNG\r\n\x1a\n":
        return raw
    if len(raw) >= 3 and raw[:3] == b"\xff\xd8\xff":
        return raw
    try:
        err = json.loads(raw.decode("utf-8"))
        if isinstance(err, dict) and "errcode" in err:
            msg = err.get("errmsg", str(err))
            logger.error("%s 微信返回错误: %s", context, err)
            raise ValueError(msg)
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    logger.error(
        "%s 响应非图片(前16字节=%r), content-type=%s",
        context,
        raw[:16],
        resp.headers.get("content-type", ""),
    )
    raise ValueError("微信返回非图片数据，请检查 access_token、路径与 env_version 配置")


async def get_access_token(*, force_refresh: bool = False) -> str:
    """
    稳定版小程序 access_token（POST cgi-bin/stable_token）。
    与普通 token 接口相比，多实例并发刷新时不易出现 40001「not latest」。
    """
    now = int(time.time())
    cache = getattr(get_access_token, "_cache", None)
    if (
        not force_refresh
        and cache
        and now - cache[1] < cache[2]
    ):
        return cache[0]

    async with _access_token_lock:
        now = int(time.time())
        cache = getattr(get_access_token, "_cache", None)
        if (
            not force_refresh
            and cache
            and now - cache[1] < cache[2]
        ):
            return cache[0]

        url = "https://api.weixin.qq.com/cgi-bin/stable_token"
        body = {
            "grant_type": "client_credential",
            "appid": settings.WECHAT_APP_ID,
            "secret": settings.WECHAT_APP_SECRET,
            "force_refresh": bool(force_refresh),
        }
        async with httpx.AsyncClient() as cli:
            ret = await cli.post(url, json=body, timeout=15)
            ret.raise_for_status()
            data = ret.json()
        if data.get("errcode"):
            logger.error("stable_token 失败: %s", data)
            raise ValueError(data.get("errmsg") or str(data))
        token = data["access_token"]
        expires_in = int(data.get("expires_in") or 7200)
        ttl = max(120, min(7000, expires_in - 300))
        get_access_token._cache = (token, now, ttl)
        return token

async def get_wxacode(path: str, scene: str = "", width: int = 280) -> bytes:
    """获取临时小程序码二进制"""
    last_err: BaseException | None = None
    for attempt in range(2):
        token = await get_access_token(force_refresh=(attempt > 0))
        url = f"https://api.weixin.qq.com/wxa/getwxacode?access_token={token}"
        body = {"path": path, "scene": scene, "width": width}
        try:
            async with httpx.AsyncClient() as cli:
                r = await cli.post(url, json=body)
                r.raise_for_status()
                return _wxacode_response_to_png(r, "getwxacode")
        except ValueError as e:
            last_err = e
            if attempt == 0 and _looks_like_stale_access_token(str(e)):
                logger.warning("getwxacode token 失效，将强制刷新后重试: %s", e)
                continue
            raise
    assert last_err is not None
    raise last_err

# ==================== 永久小程序码接口 ====================
async def get_wxacode_unlimit(scene: str, page: str, width: int = 280) -> bytes:
    """
    获取长期有效的小程序码（无限数量）
    :param scene: 场景值，长度不超过32个字符（如 "m=123"）
    :param page: 小程序页面路径，必须以 '/' 开头
    :param width: 二维码宽度
    :return: 图片二进制数据
    """
    env_ver = _normalize_wxa_env_version()
    logger.debug(
        "getwxacodeunlimit appid=%s env_version=%s page=%s scene=%s",
        settings.WECHAT_APP_ID,
        env_ver,
        page,
        scene,
    )
    payload = {
        "scene": scene,
        "page": page,
        "width": width,
        "check_path": False,          # 不校验页面是否存在（便于未发布页面）
        "env_version": env_ver,
    }
    last_err: BaseException | None = None
    for attempt in range(2):
        token = await get_access_token(force_refresh=(attempt > 0))
        url = f"https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token={token}"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json=payload, timeout=10)
                resp.raise_for_status()
                return _wxacode_response_to_png(resp, "getwxacodeunlimit")
        except ValueError as e:
            last_err = e
            if attempt == 0 and _looks_like_stale_access_token(str(e)):
                logger.warning("getwxacodeunlimit token 失效，将强制刷新后重试: %s", e)
                continue
            raise
    assert last_err is not None
    raise last_err


# ---------- URL Link（网页拉起小程序） ----------
_urllink_memo: dict[str, tuple[str, float]] = {}
_urllink_memo_lock = threading.Lock()
URLLINK_MEMO_TTL_SEC = 86400


async def generate_miniprogram_urllink(*, path: str, query: str = "") -> str:
    """
    调用 wxa/generate_urllink，返回 https 的 url_link。
    path 如 pages/index/index；query 如 a=1&b=2（不要带 ?）。
    """
    env_ver = _normalize_wxa_env_version()
    body: dict = {
        "path": path,
        "env_version": env_ver,
        "is_expire": False,
    }
    if query:
        body["query"] = query
    for attempt in range(2):
        token = await get_access_token(force_refresh=(attempt > 0))
        api_url = f"https://api.weixin.qq.com/wxa/generate_urllink?access_token={token}"
        async with httpx.AsyncClient() as client:
            resp = await client.post(api_url, json=body, timeout=15)
            resp.raise_for_status()
        data = resp.json()
        errcode = int(data.get("errcode") or 0)
        if errcode:
            logger.error("generate_urllink 失败: %s", data)
            if attempt == 0 and errcode == 40001:
                logger.warning("generate_urllink 40001，将强制刷新 stable_token 后重试")
                continue
            raise ValueError(data.get("errmsg") or str(data))
        link = data.get("url_link")
        if not link:
            logger.error("generate_urllink 无 url_link: %s", data)
            raise ValueError("微信未返回 url_link")
        return link
    raise RuntimeError("generate_urllink: 重试后仍失败")


async def get_or_create_permanent_pay_urllink(merchant_user_id: int) -> str:
    """线下永久收款页 URL Link，带 query id=商户用户ID；带进程内缓存减轻微信配额压力。"""
    query = f"id={merchant_user_id}"
    cache_key = f"pages/offline/permanentPay|{query}"
    now = time.time()
    with _urllink_memo_lock:
        hit = _urllink_memo.get(cache_key)
        if hit and now - hit[1] < URLLINK_MEMO_TTL_SEC:
            return hit[0]
    link = await generate_miniprogram_urllink(
        path="pages/offline/permanentPay",
        query=query,
    )
    with _urllink_memo_lock:
        _urllink_memo[cache_key] = (link, now)
    return link


# ---------- URL Scheme（微信内 H5 立即跳转，减少 URL Link 中间确认页） ----------
_scheme_memo: dict[str, tuple[str, float]] = {}
_scheme_memo_lock = threading.Lock()
SCHEME_MEMO_TTL_SEC = 86400


async def generate_miniprogram_openlink(*, path: str, query: str = "") -> str:
    """
    调用 wxa/generatescheme，返回 weixin://dl/business/?t=... 的 openlink。
    文档说明：可在用户打开 H5 时立即 location.href / replace 调用，适合微信内置浏览器。
    """
    env_ver = _normalize_wxa_env_version()
    jump_wxa: dict = {"path": path, "env_version": env_ver}
    if query:
        jump_wxa["query"] = query
    body: dict = {"jump_wxa": jump_wxa, "is_expire": False}
    for attempt in range(2):
        token = await get_access_token(force_refresh=(attempt > 0))
        api_url = f"https://api.weixin.qq.com/wxa/generatescheme?access_token={token}"
        async with httpx.AsyncClient() as client:
            resp = await client.post(api_url, json=body, timeout=15)
            resp.raise_for_status()
        data = resp.json()
        errcode = int(data.get("errcode") or 0)
        if errcode:
            logger.error("generatescheme 失败: %s", data)
            if attempt == 0 and errcode == 40001:
                logger.warning("generatescheme 40001，将强制刷新 stable_token 后重试")
                continue
            raise ValueError(data.get("errmsg") or str(data))
        openlink = data.get("openlink")
        if not openlink:
            logger.error("generatescheme 无 openlink: %s", data)
            raise ValueError("微信未返回 openlink")
        return openlink
    raise RuntimeError("generatescheme: 重试后仍失败")


async def get_or_create_permanent_pay_openlink(merchant_user_id: int) -> str:
    """与永久收款 URL Link 同 path/query；进程内缓存减轻微信生成配额压力。"""
    query = f"id={merchant_user_id}"
    cache_key = f"pages/offline/permanentPay|{query}"
    now = time.time()
    with _scheme_memo_lock:
        hit = _scheme_memo.get(cache_key)
        if hit and now - hit[1] < SCHEME_MEMO_TTL_SEC:
            return hit[0]
    link = await generate_miniprogram_openlink(
        path="pages/offline/permanentPay",
        query=query,
    )
    with _scheme_memo_lock:
        _scheme_memo[cache_key] = (link, now)
    return link


# ---------- 内容安全检测（msgSecCheck） ----------
async def msg_sec_check(content: str, *, scene: int = 1, openid: str | None = None) -> dict:
    """调用微信内容安全检测 msgSecCheck（version 2）。

    :param content: 待检测文本内容
    :param scene: 场景值：1=资料, 2=评论, 3=论坛, 4=社交日志
    :param openid: 用户 openid（version 2 要求，建议传入）
    :return: 微信原始响应 dict，包含 errcode / errmsg
    """
    token = await get_access_token()
    url = f"https://api.weixin.qq.com/wxa/msg_sec_check?access_token={token}"
    body: dict = {"content": content, "version": 2, "scene": scene}
    if openid:
        body["openid"] = openid
    async with httpx.AsyncClient() as cli:
        resp = await cli.post(url, json=body, timeout=10)
        resp.raise_for_status()
        return resp.json()