# core/auth.py
"""
统一认证中间件 - 支持 JWT 和 UUID 双模式
兼容开发环境和生产环境
"""

import os
import uuid
import logging
import secrets  # ✅ 新增：用于生成安全随机token
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from core.database import get_conn
from core.config import JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRE_MINUTES
from core.logging import get_logger

# 初始化日志
logger = get_logger(__name__)

# 安全方案实例
security = HTTPBearer()

# JWT 配置
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "10080"))  # 默认7天

# 认证模式开关
ENABLE_UUID_AUTH = os.getenv("ENABLE_UUID_AUTH", "1") == "1"  # 默认开启UUID模式


# ========================================
# 主认证函数 - 修复版
# ========================================

async def get_current_user(
        credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Dict[str, Any]:
    """
    统一认证入口 - 自动识别 token 类型
    - JWT: eyJ... 开头（生产环境）
    - UUID: 标准 UUID4 格式（开发环境）
    - WECHAT: 124位随机字符串（微信登录专用）
    """
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="缺少认证令牌",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raw_token = credentials.credentials or ""
    token = raw_token.strip()

    # 防御性移除 Bearer 前缀
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
        logger.warning(f"Token 包含多余的 Bearer 前缀，已自动移除: {raw_token[:20]}...")

    if not token:
        raise HTTPException(
            status_code=401,
            detail="认证令牌不能为空",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 自动识别 token 类型
    if token.startswith("eyJ"):
        # JWT 格式（生产环境）
        logger.info("检测到 JWT 令牌，使用 JWT 认证")
        return await _get_user_from_jwt(token)
    elif len(token) == 36 and '-' in token:
        # UUID 格式（36位）
        if ENABLE_UUID_AUTH:
            logger.info(f"检测到 UUID 令牌，使用 UUID 认证 - Token: {token[:8]}...")
            return await _get_user_from_uuid(token)
        else:
            raise HTTPException(
                status_code=401,
                detail="UUID认证已禁用，请使用JWT令牌",
                headers={"WWW-Authenticate": "Bearer"},
            )
    elif len(token) == 124:
        # ✅ 新增：124位微信专用token
        logger.info(f"检测到微信专用Token，长度: {len(token)}")
        return await _get_user_from_wechat_token(token)
    else:
        raise HTTPException(
            status_code=401,
            detail=f"未知Token格式（长度: {len(token)}），期望JWT、UUID(36位)或微信Token(124位)",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ✅ 新增：124位微信Token认证实现
async def _get_user_from_wechat_token(token: str) -> Dict[str, Any]:
    """微信Token认证逻辑（124位）"""
    try:
        # 严格验证长度
        if len(token) != 124:
            raise HTTPException(
                status_code=401,
                detail=f"微信Token长度必须为124位，当前: {len(token)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        logger.debug(f"验证微信Token: {token[:20]}...")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查 sessions 表是否存在
                cur.execute("SHOW TABLES LIKE 'sessions'")
                has_sessions = cur.fetchone() is not None

                if has_sessions:
                    # 使用 sessions 表（推荐方式）
                    cur.execute("""
                        SELECT s.user_id AS id, u.mobile, u.name, u.avatar_path, 
                               u.is_merchant, u.wechat_sub_mchid, u.member_level, u.status
                        FROM sessions s
                        JOIN users u ON s.user_id = u.id
                        WHERE s.token = %s AND s.expired_at > NOW()
                        LIMIT 1
                    """, (token,))
                else:
                    # 回退到 users.token 字段
                    cur.execute("""
                        SELECT id, mobile, name, avatar_path, is_merchant, 
                               wechat_sub_mchid, member_level, status
                        FROM users 
                        WHERE token = %s
                        LIMIT 1
                    """, (token,))

                user = cur.fetchone()

                if not user:
                    logger.warning(f"微信Token无效或过期: {token[:20]}...")
                    raise HTTPException(
                        status_code=401,
                        detail="认证令牌无效或已过期",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                # 检查账户状态
                if user.get("status") != 0:
                    status_msg = {1: "账号已冻结", 2: "账号已注销"}
                    raise HTTPException(
                        status_code=403,
                        detail=status_msg.get(user["status"], "账号状态异常"),
                    )

                logger.info(f"微信Token认证成功 - 用户: {user['name']}({user['mobile']})")
                return dict(user)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"微信Token认证异常: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"认证服务异常: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

# ========================================
# JWT 认证实现
# ========================================

async def _get_user_from_jwt(token: str) -> Dict[str, Any]:
    """JWT 认证逻辑"""
    try:
        # 解码 JWT
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"verify_exp": True}
        )

        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=401,
                detail="无效Token：缺少user_id",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # 查询用户信息
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, mobile, name, avatar_path, is_merchant, wechat_sub_mchid, 
                           member_level, status, created_at
                    FROM users 
                    WHERE id = %s
                    LIMIT 1
                """, (user_id,))

                user = cur.fetchone()

                if not user:
                    raise HTTPException(
                        status_code=401,
                        detail="用户不存在",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                # 检查账户状态
                if user.get("status") != 0:  # 0=正常
                    status_msg = {1: "账号已冻结", 2: "账号已注销"}
                    raise HTTPException(
                        status_code=403,
                        detail=status_msg.get(user["status"], "账号状态异常"),
                    )

                logger.info(f"JWT认证成功 - 用户: {user['name']}({user['mobile']})")
                return dict(user)

    except jwt.ExpiredSignatureError:
        logger.warning(f"Token 已过期: {token[:20]}...")
        raise HTTPException(
            status_code=401,
            detail="Token已过期，请重新登录",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except jwt.InvalidTokenError as e:
        logger.warning(f"无效Token格式: {str(e)} - {token[:20]}...")
        raise HTTPException(
            status_code=401,
            detail=f"无效的Token格式: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    except Exception as e:
        logger.error(f"JWT认证异常: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"认证服务异常: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ========================================
# UUID 认证实现（开发环境）
# ========================================

async def _get_user_from_uuid(token: str) -> Dict[str, Any]:
    """UUID 认证逻辑（仅开发环境）"""
    try:
        # 严格验证 UUID 格式
        uuid_obj = uuid.UUID(token, version=4)
        token_str = str(uuid_obj)

        logger.debug(f"验证 UUID Token: {token_str[:8]}...")

    except ValueError:
        logger.warning(f"UUID格式错误: {token[:20]}...")
        raise HTTPException(
            status_code=401,
            detail=f"认证令牌格式错误: 预期UUID4格式，但得到 {token[:20]}...",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查 sessions 表是否存在
                cur.execute("SHOW TABLES LIKE 'sessions'")
                has_sessions = cur.fetchone() is not None

                if has_sessions:
                    # 使用 sessions 表（推荐方式）
                    # ✅ 修复：明确指定返回字段名为 id（使用别名）
                    cur.execute("""
                        SELECT s.user_id AS id, u.mobile, u.name, u.avatar_path, 
                               u.is_merchant, u.wechat_sub_mchid, u.member_level, u.status
                        FROM sessions s
                        JOIN users u ON s.user_id = u.id
                        WHERE s.token = %s AND s.expired_at > NOW()
                        LIMIT 1
                    """, (token_str,))
                else:
                    # 回退到 users.token 字段（兼容旧版）
                    cur.execute("""
                        SELECT id, mobile, name, avatar_path, is_merchant, 
                               wechat_sub_mchid, member_level, status
                        FROM users 
                        WHERE token = %s
                        LIMIT 1
                    """, (token_str,))

                user = cur.fetchone()

                if not user:
                    logger.warning(f"UUID Token 无效或过期: {token_str[:8]}...")
                    raise HTTPException(
                        status_code=401,
                        detail="认证令牌无效或已过期",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                # 检查账户状态
                if user.get("status") != 0:
                    status_msg = {1: "账号已冻结", 2: "账号已注销"}
                    raise HTTPException(
                        status_code=403,
                        detail=status_msg.get(user["status"], "账号状态异常"),
                    )

                logger.info(f"UUID认证成功 - 用户: {user['name']}({user['mobile']})")
                return dict(user)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"UUID认证异常: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"认证服务异常: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ========================================
# 辅助认证函数
# ========================================

async def get_current_active_user(
        current_user: Dict[str, Any] = Depends(get_current_user)
) -> Dict[str, Any]:
    """
    获取当前激活用户（检查冻结状态）
    """
    if current_user.get("status") == 1:
        raise HTTPException(
            status_code=403,
            detail="用户账号已被冻结",
        )
    return current_user


def get_optional_user(
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)
) -> Optional[Dict[str, Any]]:
    """
    可选认证 - 未提供 token 时返回 None
    用于公开接口的权限扩展
    """
    if not credentials:
        return None

    try:
        return get_current_user(credentials)
    except HTTPException:
        return None


# ========================================
# Token 管理函数
# ========================================

def create_access_token(user_id: int, token_type: str = "uuid") -> str:
    """
    创建认证令牌
    - token_type: "uuid" | "jwt" | "wechat"  # ✅ 修改：新增 wechat 类型
    """
    if token_type == "jwt":
        return _create_jwt_token(user_id)
    elif token_type == "wechat":  # ✅ 新增：微信登录专用
        return _create_wechat_token(user_id)
    else:
        return _create_uuid_token(user_id)


def _create_uuid_token(user_id: int) -> str:
    """创建 UUID Token（开发环境）"""
    token = str(uuid.uuid4())

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查 sessions 表是否存在
                cur.execute("SHOW TABLES LIKE 'sessions'")
                has_sessions = cur.fetchone() is not None

                if has_sessions:
                    # 使用 sessions 表（推荐方式）
                    sql = """
                        INSERT INTO sessions (user_id, token, created_at, expired_at)
                        VALUES (%s, %s, NOW(), DATE_ADD(NOW(), INTERVAL 7 DAY))
                        ON DUPLICATE KEY UPDATE 
                            token = VALUES(token), 
                            expired_at = VALUES(expired_at)
                    """
                    cur.execute(sql, (user_id, token))
                else:
                    # 回退到 users.token 字段
                    cur.execute("UPDATE users SET token = %s WHERE id = %s", (token, user_id))

                conn.commit()

        logger.info(f"创建 UUID Token 成功 - 用户ID: {user_id}, Token: {token[:8]}...")
        return token

    except Exception as e:
        logger.error(f"创建 UUID Token 失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="创建认证令牌失败")


# ✅ 新增：创建124位微信专用Token
def _create_wechat_token(user_id: int) -> str:
    """创建124位微信专用Token（生产环境微信小程序登录）"""
    # 生成124位随机字符串（62字节 = 124个十六进制字符）
    token = secrets.token_hex(62)  # 124位十六进制字符串

    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查 sessions 表是否存在
                cur.execute("SHOW TABLES LIKE 'sessions'")
                if cur.fetchone():
                    # 使用 sessions 表
                    cur.execute("""
                        INSERT INTO sessions (user_id, token, created_at, expired_at)
                        VALUES (%s, %s, NOW(), DATE_ADD(NOW(), INTERVAL 7 DAY))
                        ON DUPLICATE KEY UPDATE 
                            token = VALUES(token), 
                            expired_at = VALUES(expired_at)
                    """, (user_id, token))
                else:
                    # 回退到 users.token 字段
                    cur.execute("""
                        UPDATE users SET token = %s WHERE id = %s
                    """, (token, user_id))

                conn.commit()

        logger.info(f"创建微信Token成功 - 用户ID: {user_id}, Token: {token[:20]}...")
        return token

    except Exception as e:
        logger.error(f"创建微信Token失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="创建微信认证令牌失败")

def _create_jwt_token(user_id: int) -> str:
    """创建 JWT Token（生产环境）"""
    try:
        expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRE_MINUTES)
        payload = {
            "user_id": user_id,
            "exp": expire,
            "iat": datetime.utcnow(),
            "type": "access"
        }
        token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
        logger.info(f"创建 JWT Token 成功 - 用户ID: {user_id}")
        return token
    except Exception as e:
        logger.error(f"创建 JWT Token 失败: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="创建JWT令牌失败")


def invalidate_token(token: str) -> bool:
    """
    使 token 失效（用户登出）
    返回: 是否成功
    """
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查 sessions 表
                cur.execute("SHOW TABLES LIKE 'sessions'")
                if cur.fetchone():
                    # 删除 sessions 记录
                    cur.execute("DELETE FROM sessions WHERE token = %s", (token,))
                else:
                    # 清空 users.token 字段
                    cur.execute("UPDATE users SET token = NULL WHERE token = %s", (token,))

                deleted = cur.rowcount > 0
                conn.commit()

                if deleted:
                    logger.info(f"Token 已失效: {token[:8]}...")

                return deleted

    except Exception as e:
        logger.error(f"注销 Token 失败: {str(e)}", exc_info=True)
        return False


# ========================================
# 数据库辅助函数
# ========================================

def ensure_sessions_table():
    """确保 sessions 表存在（推荐方式）"""
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS sessions (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        token VARCHAR(256) NOT NULL UNIQUE,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        expired_at DATETIME NOT NULL,
                        INDEX idx_token (token),
                        INDEX idx_user (user_id),
                        INDEX idx_expired (expired_at)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """)
                conn.commit()
        logger.info("sessions 表检查/创建成功")
    except Exception as e:
        logger.warning(f"sessions 表创建失败（可能已存在）: {str(e)}")


# 启动时检查 sessions 表
ensure_sessions_table()