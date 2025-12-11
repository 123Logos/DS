# services/wechat_service.py - 微信登录服务
import uuid
import pymysql
import jwt
import datetime
from typing import Optional, Dict, Any
from fastapi import HTTPException

from core.database import get_conn
from core.config import WECHAT_APP_ID, WECHAT_APP_SECRET
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
                cur.execute("SELECT id FROM users WHERE openid=%s", (openid,))
                return cur.fetchone()

    @staticmethod
    def register_user(openid: str, nick_name: str) -> int:
        """为微信用户创建账号，自动生成必填字段"""
        # 生成占位手机号，保证唯一
        mobile = f"wx_{openid[:20]}"
        pwd_hash = hash_pwd(uuid.uuid4().hex)

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 唯一推荐码
                code = _generate_code()
                cur.execute("SELECT 1 FROM users WHERE referral_code=%s", (code,))
                while cur.fetchone():
                    code = _generate_code()
                    cur.execute("SELECT 1 FROM users WHERE referral_code=%s", (code,))

                # 确保占位手机号不冲突
                cur.execute("SELECT 1 FROM users WHERE mobile=%s", (mobile,))
                idx = 1
                base_mobile = mobile
                while cur.fetchone():
                    mobile = f"{base_mobile}_{idx}"
                    cur.execute("SELECT 1 FROM users WHERE mobile=%s", (mobile,))
                    idx += 1

                cur.execute(
                    "INSERT INTO users(openid, mobile, password_hash, name, member_points, merchant_points, withdrawable_balance, status, referral_code) "
                    "VALUES (%s, %s, %s, %s, 0, 0, 0, %s, %s)",
                    (openid, mobile, pwd_hash, nick_name, int(UserStatus.NORMAL), code)
                )
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
