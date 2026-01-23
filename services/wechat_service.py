# services/wechat_service.py - 微信登录服务
import uuid
import pymysql
import jwt
import datetime
import requests
from typing import Optional, Dict, Any,Tuple
from fastapi import HTTPException

from core.logging import get_logger
from core.database import get_conn
from core.config import WECHAT_APP_ID, WECHAT_APP_SECRET
from core.table_access import build_dynamic_select, _quote_identifier
from services.user_service import hash_pwd, UserStatus, _generate_code

logger = get_logger(__name__)

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

                cols_sql = ",".join([_quote_identifier(c) for c in insert_cols])
                placeholders = ",".join(["%s"] * len(insert_cols))
                sql = f"INSERT INTO {_quote_identifier('users')}({cols_sql}) VALUES ({placeholders})"
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
        # 确保 payload 中不包含 Decimal 或其他不可序列化对象
        uid = int(user_id)
        exp_dt = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        exp_ts = int(exp_dt.timestamp())
        payload = {
            "user_id": uid,
            "exp": exp_ts
        }
        token = jwt.encode(payload, "your_secret_key", algorithm="HS256")
        return token

    @staticmethod
    def generate_wxacode(scene: str, page: str = "pages/index/index") -> Optional[bytes]:
        """
        调用微信接口生成小程序码
        :param scene: 场景值（推荐码）
        :param page: 小程序页面路径
        :return: 图片二进制数据或 None
        """
        try:
            # 获取 access_token
            token_url = (
                f"https://api.weixin.qq.com/cgi-bin/token?"
                f"grant_type=client_credential&appid={WECHAT_APP_ID}&secret={WECHAT_APP_SECRET}"
            )
            resp = requests.get(token_url, timeout=10).json()

            access_token = resp.get("access_token")
            if not access_token:
                logger.error(f"获取 access_token 失败: {resp}")
                return None

            # 调用微信生成小程序码接口
            qr_url = f"https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token={access_token}"

            data = {
                "scene": scene,
                "page": page,
                "width": 280,
                "is_hyaline": True,  # 透明背景
                "check_path": False  # 不校验页面路径（适用于未发布页面）
            }

            resp = requests.post(qr_url, json=data, timeout=10)

            # 微信返回的是图片字节流或 JSON 错误信息
            content_type = resp.headers.get("Content-Type", "")
            if "image" in content_type:
                return resp.content
            else:
                logger.error(f"生成小程序码失败: {resp.text}")
                return None

        except Exception as e:
            logger.exception(f"生成小程序码异常: {e}")
            return None

    @staticmethod
    def get_openid_by_code(code: str) -> Tuple[str, str]:
        """code 换 openid 和 session_key"""
        url = f"https://api.weixin.qq.com/sns/jscode2session?appid={WECHAT_APP_ID}&secret={WECHAT_APP_SECRET}&js_code={code}&grant_type=authorization_code"
        resp = requests.get(url, timeout=10).json()

        if "errcode" in resp and resp["errcode"] != 0:
            raise ValueError(f"微信接口错误: {resp.get('errmsg')}")

        return resp["openid"], resp["session_key"]

    @staticmethod
    def decrypt_phone_number(session_key: str, encrypted_data: str, iv: str) -> str:
        """AES解密微信手机号"""
        try:
            # base64解码
            session_key_bytes = base64.b64decode(session_key)
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv_bytes = base64.b64decode(iv)

            # AES解密
            cipher = AES.new(session_key_bytes, AES.MODE_CBC, iv_bytes)
            decrypted = cipher.decrypt(encrypted_bytes)

            # 去除PKCS#7填充
            pad_len = decrypted[-1]
            result = json.loads(decrypted[:-pad_len].decode('utf-8'))

            # 校验AppID
            if result.get('watermark', {}).get('appid') != WECHAT_APP_ID:
                raise ValueError("AppID不匹配")

            return result['phoneNumber']

        except Exception as e:
            logger.error(f"解密失败: {e}")
            raise ValueError("手机号解密失败，请检查参数是否正确")