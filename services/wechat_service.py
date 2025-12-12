# services/wechat_service.py - 微信登录服务
import uuid
import pymysql
import jwt
import datetime
from typing import Optional, Dict, Any
from fastapi import HTTPException

from core.database import get_conn
from core.config import WECHAT_APP_ID, WECHAT_APP_SECRET
from core.table_access import build_dynamic_select
from services.user_service import hash_pwd, UserStatus, _generate_code


class WechatService:
    """微信登录服务"""

    @staticmethod
    def ensure_openid_column():
        """确保 users 表存在 openid 字段（兼容旧库）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SHOW COLUMNS FROM users LIKE 'openid'")
                exists = cur.fetchone()
                if not exists:
                    try:
                        cur.execute("ALTER TABLE users ADD COLUMN openid VARCHAR(64) UNIQUE")
                        conn.commit()
                    except pymysql.err.InternalError as e:
                        if e.args[0] == 1060:  # 字段已存在
                            return
                        raise

    @staticmethod
    def check_user_by_openid(openid: str) -> Optional[Dict[str, Any]]:
        """通过openid查询用户"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur,
                    "users",
                    where_clause="openid=%s",
                    select_fields=["id"]
                )
                cur.execute(select_sql, (openid,))
                return cur.fetchone()

    @staticmethod
    def register_user(openid: str, nick_name: str) -> int:
        """为微信用户创建账号，自动生成必填字段"""
        # 生成占位手机号，保证唯一
        mobile = f"wx_{openid[:20]}"
        pwd_hash = hash_pwd(uuid.uuid4().hex)

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 获取 users 表字段，动态构建插入语句以兼容老表
                cur.execute("SHOW COLUMNS FROM users")
                cols = [r["Field"] for r in cur.fetchall()]

                desired = [
                    "openid", "mobile", "password_hash", "name",
                    "member_points", "merchant_points", "withdrawable_balance",
                    "status", "referral_code"
                ]
                insert_cols = [c for c in desired if c in cols]

                # 确保 mobile/password_hash 存在
                if "mobile" not in insert_cols or "password_hash" not in insert_cols:
                    raise RuntimeError("数据库 users 表缺少必要字段，请检查表结构")

                # 如果支持 referral_code，则生成唯一推荐码
                code = None
                if "referral_code" in insert_cols:
                    code = _generate_code()
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="referral_code=%s",
                        select_fields=["1"]
                    )
                    cur.execute(select_sql, (code,))
                    while cur.fetchone():
                        code = _generate_code()
                        select_sql = build_dynamic_select(
                            cur,
                            "users",
                            where_clause="referral_code=%s",
                            select_fields=["1"]
                        )
                        cur.execute(select_sql, (code,))

                # 确保占位手机号不冲突
                select_sql = build_dynamic_select(
                    cur,
                    "users",
                    where_clause="mobile=%s",
                    select_fields=["1"]
                )
                cur.execute(select_sql, (mobile,))
                idx = 1
                base_mobile = mobile
                while cur.fetchone():
                    mobile = f"{base_mobile}_{idx}"
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="mobile=%s",
                        select_fields=["1"]
                    )
                    cur.execute(select_sql, (mobile,))
                    idx += 1

                vals = []
                for col in insert_cols:
                    if col == "openid":
                        vals.append(openid)
                    elif col == "mobile":
                        vals.append(mobile)
                    elif col == "password_hash":
                        vals.append(pwd_hash)
                    elif col == "name":
                        vals.append(nick_name)
                    elif col in ("member_points", "merchant_points"):
                        vals.append(0)
                    elif col == "withdrawable_balance":
                        vals.append(0)
                    elif col == "status":
                        vals.append(int(UserStatus.NORMAL))
                    elif col == "referral_code":
                        vals.append(code)
                    else:
                        vals.append(None)

                cols_sql = ",".join(insert_cols)
                placeholders = ",".join(["%s"] * len(insert_cols))
                sql = f"INSERT INTO users({cols_sql}) VALUES ({placeholders})"
                cur.execute(sql, tuple(vals))
                conn.commit()
                return cur.lastrowid

    @staticmethod
    def get_openid_by_code(code: str) -> tuple[str, str]:
        """通过code换取openid和session_key"""
        # 延迟导入 requests，避免 Windows multiprocessing 导入问题
        import requests
        
        if not WECHAT_APP_ID or not WECHAT_APP_SECRET:
            raise HTTPException(status_code=500, detail="未配置微信小程序 AppId/Secret，请在 .env 中设置 WECHAT_APP_ID 与 WECHAT_APP_SECRET")

        url = f"https://api.weixin.qq.com/sns/jscode2session?appid={WECHAT_APP_ID}&secret={WECHAT_APP_SECRET}&js_code={code}&grant_type=authorization_code"
        response = requests.get(url)
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="微信接口调用失败")

        wechat_data = response.json()
        openid = wechat_data.get('openid')
        session_key = wechat_data.get('session_key')

        if not openid or not session_key:
            error_msg = wechat_data.get('errmsg', '未知错误')
            raise HTTPException(status_code=500, detail=f"无法获取openid或session_key: {error_msg}")

        return openid, session_key

    @staticmethod
    def generate_token(user_id: int) -> str:
        """生成JWT token"""
        payload = {
            "user_id": user_id,
            "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        }
        token = jwt.encode(payload, "your_secret_key", algorithm="HS256")
        return token
