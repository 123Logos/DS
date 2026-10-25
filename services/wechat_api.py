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
            errcode = err.get("errcode")
            logger.error("%s 微信返回错误: errcode=%s", context, errcode)
            raise ValueError(f"微信返回图片错误 (errcode={errcode})")
    except (UnicodeDecodeError, json.JSONDecodeError):
        pass
    logger.error("%s 响应非图片: response_bytes=%s content_type=%s",
                 context, len(raw), resp.headers.get("content-type", ""))
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
            logger.error("stable_token request failed: errcode=%s", data.get("errcode"))
            raise ValueError("stable_token request failed")
        token = data["access_token"]
        expires_in = int(data.get("expires_in") or 7200)
        ttl = max(120, min(7000, expires_in - 300))
        get_access_token._cache = (token, now, ttl)
        return token


async def media_check_async(
    *,
    media_url: str,
    openid: str,
    scene: int = 1,
) -> str:
    """提交微信小程序图片内容安全异步检测，返回 trace_id。"""
    if not media_url or not media_url.startswith(("https://", "http://")):
        raise ValueError("media_url 必须是可被微信访问的完整 URL")
    if not openid:
        raise ValueError("缺少微信用户 openid")

    payload = {
        "media_url": media_url,
        "media_type": 2,
        "version": 2,
        "scene": int(scene),
        "openid": openid,
    }
    for attempt in range(2):
        token = await get_access_token(force_refresh=attempt > 0)
        url = f"https://api.weixin.qq.com/wxa/media_check_async?access_token={token}"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(url, json=payload, timeout=15)
                response.raise_for_status()
                data = response.json()
            if data.get("errcode"):
                message = str(data.get("errmsg") or data)
                if attempt == 0 and _looks_like_stale_access_token(message):
                    continue
                raise ValueError(message)
            trace_id = data.get("trace_id")
            if not trace_id:
                raise ValueError("微信内容安全接口未返回 trace_id")
            return str(trace_id)
        except (httpx.HTTPError, ValueError):
            if attempt == 0:
                raise
            raise

    raise ValueError("微信内容安全接口调用失败")

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
                logger.warning("getwxacode token refresh retry: error_type=%s", type(e).__name__)
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
                logger.warning("getwxacodeunlimit token refresh retry: error_type=%s", type(e).__name__)
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
            logger.error("generate_urllink failed: errcode=%s", errcode)
            if attempt == 0 and errcode == 40001:
                logger.warning("generate_urllink token refresh retry")
                continue
            raise ValueError("generate_urllink request failed")
        link = data.get("url_link")
        if not link:
            logger.error("generate_urllink response missing link")
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
            logger.error("generatescheme failed: errcode=%s", errcode)
            if attempt == 0 and errcode == 40001:
                logger.warning("generatescheme token refresh retry")
                continue
            raise ValueError("generatescheme request failed")
        openlink = data.get("openlink")
        if not openlink:
            logger.error("generatescheme response missing openlink")
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
async def msg_sec_check(content: str, *, scene: int = 1, openid: str) -> dict:
    """调用微信 v2；openid 必须来自服务端认证身份，文本上限 2500 字。"""
    if not isinstance(content, str) or not content.strip() or len(content) > 2500:
        raise ValueError("文本必须为非空字符串且不超过2500字")
    if type(scene) is not int or scene not in (1, 2, 3, 4):
        raise ValueError("无效的内容安全场景")
    if not isinstance(openid, str) or not openid.strip():
        raise ValueError("缺少微信用户 openid")
    token = await get_access_token()
    url = f"https://api.weixin.qq.com/wxa/msg_sec_check?access_token={token}"
    body = {"content": content, "version": 2, "scene": scene, "openid": openid}
    async with httpx.AsyncClient() as cli:
        resp = await cli.post(url, json=body, timeout=10)
        resp.raise_for_status()
        return resp.json()


async def check_text_security(content: str, *, openid: str, scene: int = 1) -> str:
    """统一判定：只有 v2 明确 pass 才允许写入；未知结果视为不可用。"""
    if not openid:
        return "unavailable"
    try:
        data = await msg_sec_check(content, openid=openid, scene=scene)
    except Exception as exc:
        # HTTP 异常包含带 access_token 的 URL，禁止记录异常正文或 traceback。
        logger.warning("文本审核调用失败: type=%s", type(exc).__name__)
        return "unavailable"
    if not isinstance(data, dict) or type(data.get("errcode")) is not int:
        return "unavailable"
    if data["errcode"] == 87014:
        return "risky"
    if data["errcode"] != 0:
        logger.warning("文本审核上游错误: errcode=%s", data["errcode"])
        return "unavailable"
    result = data.get("result")
    suggest = result.get("suggest") if isinstance(result, dict) else None
    return suggest if suggest in ("pass", "risky", "review") else "unavailable"


async def require_safe_text(content: str, *, openid: str, scene: int = 1) -> None:
    """写入端必须独立审核，不能信任客户端曾调用预检的声明。"""
    from fastapi import HTTPException

    decision = await check_text_security(content, openid=openid, scene=scene)
    if decision == "unavailable":
        raise HTTPException(status_code=503, detail="内容审核暂不可用，请稍后重试")
    if decision != "pass":
        raise HTTPException(status_code=400, detail="内容未通过安全审核，请修改后重试")
