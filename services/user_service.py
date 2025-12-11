import uuid
import bcrypt
from typing import Optional
from enum import IntEnum
from core.database import get_conn
import string
import random  # 在文件头部加这两行
from enum import IntEnum




# ========== 用户状态枚举 ==========
class UserStatus(IntEnum):
    NORMAL = 0  # 正常
    FROZEN = 1  # 冻结（不能登录、不能下单）
    DELETED = 2  # 已注销（逻辑删除，所有业务拦截）


def hash_pwd(pwd: str) -> str:
    """密码加密"""
    return bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()


def verify_pwd(pwd: str, hashed: str) -> bool:
    """密码校验"""
    return bcrypt.checkpw(pwd.encode(), hashed.encode())



def _generate_code(length: int = 6) -> str:
    """生成 6 位不含 0O1I 的随机码"""
    chars = string.ascii_uppercase.replace('O', '').replace('I', '') + \
            string.digits.replace('0', '').replace('1', '')
    return ''.join(random.choices(chars, k=length))

class UserService:
    @staticmethod
    def register(mobile: str, pwd: str, name: Optional[str] = None, referrer_mobile: Optional[str] = None) -> int:
        """用户注册"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE mobile=%s", (mobile,))
                if cur.fetchone():
                    raise ValueError("手机号已注册")
                pwd_hash = hash_pwd(pwd)

                # 获取 users 表的可用字段，动态构建插入语句以兼容老表结构
                cur.execute("SHOW COLUMNS FROM users")
                cols = [r["Field"] for r in cur.fetchall()]

                desired = [
                    "mobile", "password_hash", "name",
                    "member_points", "merchant_points", "withdrawable_balance",
                    "status", "referral_code"
                ]
                insert_cols = [c for c in desired if c in cols]

                # 必需字段检查
                if "mobile" not in insert_cols or "password_hash" not in insert_cols:
                    raise RuntimeError("数据库 users 表缺少必要字段，请检查表结构")

                # 如果支持 referral_code，则生成唯一推荐码
                code = None
                if "referral_code" in insert_cols:
                    code = _generate_code()
                    cur.execute("SELECT 1 FROM users WHERE referral_code=%s", (code,))
                    while cur.fetchone():
                        code = _generate_code()
                        cur.execute("SELECT 1 FROM users WHERE referral_code=%s", (code,))

                # 为每个插入列准备对应的值
                vals = []
                for col in insert_cols:
                    if col == "mobile":
                        vals.append(mobile)
                    elif col == "password_hash":
                        vals.append(pwd_hash)
                    elif col == "name":
                        vals.append(name)
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
                uid = cur.lastrowid
                conn.commit()

                # 3. 绑定推荐人（原逻辑不变）
                if referrer_mobile:
                    cur.execute("SELECT id FROM users WHERE mobile=%s", (referrer_mobile,))
                    ref = cur.fetchone()
                    if ref:
                        cur.execute("INSERT INTO user_referrals(user_id, referrer_id) VALUES (%s,%s)",
                                    (uid, ref["id"]))
                return uid

    @staticmethod
    def login(mobile: str, pwd: str) -> dict:
        """用户登录"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id, password_hash, member_level, status FROM users WHERE mobile=%s",
                    (mobile,)
                )
                row = cur.fetchone()
                if not row or not verify_pwd(pwd, row["password_hash"]):
                    raise ValueError("手机号或密码错误")

                # 检查用户状态
                status = row["status"]
                if status == UserStatus.FROZEN:
                    raise ValueError("账号已被冻结，请联系客服")
                if status == UserStatus.DELETED:
                    raise ValueError("账号已注销")

                token = str(uuid.uuid4())
                return {"uid": row["id"], "level": row["member_level"], "token": token}

    @staticmethod
    def upgrade_one_star(mobile: str) -> int:
        """用户升级一星"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, member_level FROM users WHERE mobile=%s", (mobile,))
                row = cur.fetchone()
                if not row:
                    raise ValueError("用户不存在")
                current = row["member_level"]
                if current >= 6:
                    raise ValueError("已是最高星级（6星）")
                new_level = current + 1
                cur.execute("UPDATE users SET member_level=%s, level_changed_at=NOW() WHERE mobile=%s",
                            (new_level, mobile))
                return new_level

    @staticmethod
    def bind_referrer(mobile: str, referrer_mobile: str):
        """绑定推荐人"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE mobile=%s", (mobile,))
                u = cur.fetchone()
                if not u:
                    raise ValueError("被推荐人不存在")
                cur.execute("SELECT id FROM users WHERE mobile=%s", (referrer_mobile,))
                ref = cur.fetchone()
                if not ref:
                    raise ValueError("推荐人不存在")
                cur.execute(
                    "INSERT INTO user_referrals(user_id, referrer_id) VALUES (%s,%s) ON DUPLICATE KEY UPDATE referrer_id=%s",
                    (u["id"], ref["id"], ref["id"])
                )

    @staticmethod
    def set_level(mobile: str, new_level: int, reason: str = "后台手动调整"):
        """设置会员等级"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, member_level FROM users WHERE mobile=%s", (mobile,))
                row = cur.fetchone()
                if not row:
                    raise ValueError("用户不存在")
                old_level = row["member_level"]
                if old_level == new_level:
                    return old_level

                # 更新用户等级
                cur.execute("UPDATE users SET member_level=%s, level_changed_at=NOW() WHERE mobile=%s",
                            (new_level, mobile))
                conn.commit()
                return new_level

    @staticmethod
    def grant_merchant(mobile: str) -> bool:
        """授予商家权限"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE users SET is_merchant=1 WHERE mobile=%s", (mobile,))
                return cur.rowcount > 0

    @staticmethod
    def is_merchant(mobile: str) -> bool:
        """检查是否为商家"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT is_merchant FROM users WHERE mobile=%s", (mobile,))
                row = cur.fetchone()
                return bool(row and row['is_merchant'])

    @staticmethod
    def set_status(mobile: str, new_status: UserStatus, reason: str = "后台调整") -> bool:
        """设置用户状态"""
        if new_status not in (UserStatus.NORMAL, UserStatus.FROZEN, UserStatus.DELETED):
            raise ValueError("非法状态值")

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id, status FROM users WHERE mobile=%s", (mobile,))
                row = cur.fetchone()
                if not row:
                    raise ValueError("用户不存在")

                old_status = row["status"]
                if old_status == int(new_status):
                    return False  # 无变化

                # 更新状态（重点：把枚举转 int）
                cur.execute(
                    "UPDATE users SET status=%s WHERE mobile=%s",
                    (int(new_status), mobile)
                )
                conn.commit()
                return cur.rowcount > 0
