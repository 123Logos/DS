# core/rate_limiter.py
import time
import threading
import asyncio
from functools import wraps
from collections import defaultdict, deque
from typing import Callable, Any, Optional, DefaultDict

from core.config import settings
from core.logging import get_logger
from core.redis_client import get_redis_client

logger = get_logger(__name__)


def _redis_sliding_allow(key: str, max_calls: int, period: int) -> tuple[bool, float]:
    """
    Redis 全局限流（多 worker 共享）。
    返回 (是否允许, 需等待秒数)。
    """
    client = get_redis_client()
    if not client:
        return True, 0.0
    now = time.time()
    window_key = f"wx:rl:{key}"
    try:
        pipe = client.pipeline()
        pipe.zremrangebyscore(window_key, 0, now - period)
        pipe.zadd(window_key, {str(now): now})
        pipe.zcard(window_key)
        pipe.expire(window_key, period + 1)
        _, _, count, _ = pipe.execute()
        if count > max_calls:
            oldest = client.zrange(window_key, 0, 0, withscores=True)
            wait = period - (now - oldest[0][1]) if oldest else period
            client.zrem(window_key, str(now))
            return False, max(0.0, wait)
        return True, 0.0
    except Exception as e:
        logger.warning("Redis 全局限流失败，放行: %s", e)
        return True, 0.0


class RateLimiter:
    """微信支付V3 API专用限流器（线程安全，支持异步）

    Redis 可用且 WX_GLOBAL_RATE_LIMIT_ENABLED 时走全局限流；
    否则回退进程内滑动窗口。
    """

    def __init__(self, max_calls: int = 5, period: int = 1):
        self.max_calls = max_calls
        self.period = period
        self.calls = defaultdict(deque)
        self.lock = threading.Lock()
        logger.debug("RateLimiter初始化: max_calls=%s, period=%ss", max_calls, period)

    def __call__(self, func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):
            return self._async_decorator(func)
        return self._sync_decorator(func)

    def _acquire(self, key: str) -> Optional[float]:
        if settings.WX_GLOBAL_RATE_LIMIT_ENABLED and get_redis_client():
            allowed, wait = _redis_sliding_allow(key, self.max_calls, self.period)
            if not allowed:
                logger.warning(
                    "微信接口全局限流触发: key=%s 当前窗口>%s/%ss, 需等待%.2fs",
                    key,
                    self.max_calls,
                    self.period,
                    wait,
                )
                return wait
            return None
        with self.lock:
            now = time.time()
            call_queue = self.calls[key]
            self._cleanup_expired(call_queue, now)
            sleep_time = self._check_limit(call_queue, now)
            call_queue.append(now)
            return sleep_time

    def _sync_decorator(self, func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            sub_mchid = args[1] if len(args) > 1 else None
            if not sub_mchid:
                logger.warning("无法提取sub_mchid，限流器跳过: %s", func.__name__)
                return func(*args, **kwargs)
            key = f"{func.__name__}_{sub_mchid}"
            sleep_time = self._acquire(key)
            if sleep_time:
                time.sleep(sleep_time)
                sleep_time2 = self._acquire(key)
                if sleep_time2:
                    raise Exception("限流异常：等待后仍超限，请求过于频繁")
            return func(*args, **kwargs)

        return wrapper

    def _async_decorator(self, func: Callable) -> Callable:
        @wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            sub_mchid = args[1] if len(args) > 1 else None
            if not sub_mchid:
                return await func(*args, **kwargs)
            key = f"{func.__name__}_{sub_mchid}"
            sleep_time = self._acquire(key)
            if sleep_time:
                await asyncio.sleep(sleep_time)
                sleep_time2 = self._acquire(key)
                if sleep_time2:
                    raise Exception("限流异常：等待后仍超限，请求过于频繁")
            return await func(*args, **kwargs)

        return async_wrapper

    def _cleanup_expired(self, queue: deque, now: float):
        while queue and now - queue[0] > self.period:
            queue.popleft()

    def _check_limit(self, queue: deque, now: float) -> Optional[float]:
        if len(queue) >= self.max_calls:
            wait_time = self.period - (now - queue[0])
            return max(0, wait_time)
        return None

    def get_stats(self, key: Optional[str] = None) -> dict:
        with self.lock:
            now = time.time()
            if key:
                queue = self.calls.get(key, deque())
                self._cleanup_expired(queue, now)
                return {"key": key, "current_calls": len(queue)}
            stats = {}
            for k, q in self.calls.items():
                self._cleanup_expired(q, now)
                stats[k] = {"current_calls": len(q)}
            return stats

    def reset(self, key: Optional[str] = None):
        with self.lock:
            if key:
                self.calls.pop(key, None)
            else:
                self.calls.clear()


settlement_rate_limiter = RateLimiter(
    max_calls=settings.WX_SETTLEMENT_MAX_PER_SEC,
    period=1,
)
query_rate_limiter = RateLimiter(
    max_calls=settings.WX_QUERY_MAX_PER_SEC,
    period=1,
)


class SimpleWindowIPRateLimiter:
    """按客户端 IP 的滑动窗口计数；超过阈值则拒绝（用于公开 H5 落地页）。"""

    def __init__(self, max_calls: int, period_seconds: float):
        self.max_calls = max_calls
        self.period_seconds = period_seconds
        self._by_ip: DefaultDict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, ip: str) -> bool:
        with self._lock:
            now = time.time()
            q = self._by_ip[ip]
            while q and now - q[0] > self.period_seconds:
                q.popleft()
            if len(q) >= self.max_calls:
                return False
            q.append(now)
            return True


pay_bridge_ip_limiter = SimpleWindowIPRateLimiter(max_calls=60, period_seconds=60.0)
