"""All supported credentials are backed by authoritative, revocable sessions."""
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.concurrency import run_in_threadpool
from core.database import get_conn
from core.config import settings, JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_MINUTES, ENABLE_UUID_AUTH, parse_csv_ids

security = HTTPBearer(auto_error=False)




async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    return await run_in_threadpool(_authenticate, credentials)


def _authenticate(credentials: HTTPAuthorizationCredentials) -> Dict[str, Any]:
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(401, "缺少认证令牌", headers={"WWW-Authenticate": "Bearer"})
    token = credentials.credentials
    session_token = token
    expected_user = None
    if token.startswith("eyJ"):
        try:
            payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM],
                                 options={"require": ["exp", "iat", "sid", "user_id", "type"]})
            if payload["type"] != "access" or not isinstance(payload["sid"], str):
                raise jwt.InvalidTokenError()
            session_token = payload["sid"]
            expected_user = int(payload["user_id"])
        except (jwt.InvalidTokenError, ValueError, TypeError):
            raise HTTPException(401, "认证令牌无效或已过期")
    elif len(token) == 36:
        if not ENABLE_UUID_AUTH:
            raise HTTPException(401, "UUID认证已禁用")
        try:
            if str(uuid.UUID(token, version=4)) != token:
                raise ValueError()
        except ValueError:
            raise HTTPException(401, "认证令牌无效")
    elif len(token) != 124:
        raise HTTPException(401, "认证令牌无效")
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT u.id,u.mobile,u.name,u.avatar_path,u.is_merchant,
                    u.wechat_sub_mchid,u.member_level,u.status,u.openid
                    FROM sessions s JOIN users u ON u.id=s.user_id
                    WHERE s.token=%s AND s.expired_at>NOW() LIMIT 1""", (session_token,))
                user = cur.fetchone()
    except Exception:
        raise HTTPException(503, "认证服务暂不可用")
    if not user or (expected_user is not None and user["id"] != expected_user):
        raise HTTPException(401, "认证令牌无效或已过期")
    if user["status"] != 0:
        raise HTTPException(403, "账号已冻结或注销")
    return dict(user)


def is_platform_admin(user: Dict[str, Any]) -> bool:
    try:
        return int(user.get("id")) in parse_csv_ids(settings.ADMIN_USER_IDS)
    except (ValueError, TypeError):
        return False


async def require_platform_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if not is_platform_admin(user):
        raise HTTPException(403, "需要平台管理员权限")
    return user


async def require_admin_or_merchant(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    if not is_platform_admin(user) and not user.get("is_merchant"):
        raise HTTPException(403, "需要商家或平台管理员权限")
    return user




async def get_optional_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[Dict[str, Any]]:
    if credentials is None:
        return None
    return await get_current_user(credentials)


def create_access_token(user_id: int, token_type: str = "uuid", expected_password_hash: str | None = None,
                        expected_password: str | None = None, expected_mobile: str | None = None) -> str:
    user_id = int(user_id)
    if token_type not in {"uuid", "wechat", "jwt"}:
        raise ValueError("Unsupported token type")
    if token_type == "uuid" and not ENABLE_UUID_AUTH:
        token_type = "jwt"
    expires = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
    sid = secrets.token_hex(32)
    token = (str(uuid.uuid4()) if token_type == "uuid" else secrets.token_hex(62))
    if token_type == "jwt":
        token = jwt.encode({"user_id": user_id, "sid": sid, "type": "access",
                            "iat": datetime.utcnow(), "exp": expires}, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT status,password_hash,mobile FROM users WHERE id=%s FOR UPDATE", (user_id,))
            user = cur.fetchone()
            if not user or user["status"] != 0:
                raise HTTPException(403, "账号不可用")
            if expected_password_hash is not None and user["password_hash"] != expected_password_hash:
                raise HTTPException(401, "凭据已变更，请重新登录")
            if expected_mobile is not None and user["mobile"] != expected_mobile:
                raise HTTPException(401, "身份已变更，请重新登录")
            if expected_password is not None:
                from services.user_service import verify_pwd
                if not verify_pwd(expected_password, user["password_hash"]):
                    raise HTTPException(401, "凭据已变更，请重新登录")
            cur.execute("INSERT INTO sessions(user_id,token,expired_at) VALUES(%s,%s,%s)",
                        (user_id, sid if token_type == "jwt" else token, expires))
            conn.commit()
    return token


def invalidate_token(token: str) -> bool:
    if token.startswith("eyJ"):
        try:
            token = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM],
                               options={"require": ["sid", "exp"]})["sid"]
        except jwt.InvalidTokenError:
            return False
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE token=%s", (token,))
            changed = cur.rowcount > 0
            conn.commit()
    return changed
