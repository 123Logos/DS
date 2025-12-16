import uuid
import bcrypt
from typing import Optional
from enum import IntEnum
from core.database import get_conn
from core.table_access import build_dynamic_select, _quote_identifier
import string
import random


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
    def register(mobile: str, pwd: str, name: Optional[str] = None,
                 referrer_mobile: Optional[str] = None) -> int:
        """用户注册"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 手机号重复检查
                select_sql = build_dynamic_select(
                    cur, "users", where_clause="mobile=%s", select_fields=["id"])
                cur.execute(select_sql, (mobile,))
                if cur.fetchone():
                    raise ValueError("手机号已注册")

                pwd_hash = hash_pwd(pwd)

                # 2. 动态列检查
                cur.execute("SHOW COLUMNS FROM users")
                cols = [r["Field"] for r in cur.fetchall()]
                desired = [
                    "mobile", "password_hash", "name",
                    "member_points", "merchant_points", "withdrawable_balance",
                    "status", "referral_code"
                ]
                insert_cols = [c for c in desired if c in cols]
                if "mobile" not in insert_cols or "password_hash" not in insert_cols:
                    raise RuntimeError("数据库 users 表缺少必要字段，请检查表结构")

                # 3. 生成唯一推荐码
                code = None
                if "referral_code" in insert_cols:
                    while True:
                        code = _generate_code()
                        # ====== 绕过 build_dynamic_select，直接写合法 SQL ======
                        cur.execute(
                            "SELECT 1 FROM users WHERE referral_code=%s LIMIT 1",
                            (code,)
                        )
                        if not cur.fetchone():        # 没冲突即可用
                            break

                # 4. 组装插入语句
                vals = []
                for col in insert_cols:
                    if col == "mobile":
                        vals.append(mobile)
                    elif col == "password_hash":
                        vals.append(pwd_hash)
                    elif col == "name":
                        vals.append(name if name is not None else "微信用户")
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
                uid = cur.lastrowid
                conn.commit()

                # 5. 绑定推荐人
                if referrer_mobile:
                    select_sql = build_dynamic_select(
                        cur, "users", where_clause="mobile=%s", select_fields=["id"])
                    cur.execute(select_sql, (referrer_mobile,))
                    ref = cur.fetchone()
                    if ref:
                        cur.execute(
                            "INSERT INTO user_referrals(user_id, referrer_id) VALUES (%s,%s)",
                            (uid, ref["id"])
                        )
                return uid

    # ---------------- 以下代码未做任何改动 ----------------
    @staticmethod
    def login(mobile: str, pwd: str) -> dict:
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur, "users", where_clause="mobile=%s",
                    select_fields=["id", "password_hash", "member_level", "status"])
                cur.execute(select_sql, (mobile,))
                row = cur.fetchone()
                if not row or not verify_pwd(pwd, row["password_hash"]):
                    raise ValueError("手机号或密码错误")
                status = row["status"]
                if status == UserStatus.FROZEN:
                    raise ValueError("账号已被冻结，请联系客服")
                if status == UserStatus.DELETED:
                    raise ValueError("账号已注销")
                token = str(uuid.uuid4())
                return {"uid": row["id"], "level": row["member_level"], "token": token}

    @staticmethod
    def upgrade_one_star(mobile: str) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur, "users", where_clause="mobile=%s",
                    select_fields=["id", "member_level"])
                cur.execute(select_sql, (mobile,))
                row = cur.fetchone()
                if not row:
                    raise ValueError("用户不存在")
                current = row["member_level"]
                if current >= 6:
                    raise ValueError("已是最高星级（6星）")
                new_level = current + 1
                cur.execute(
                    "UPDATE users SET member_level=%s, level_changed_at=NOW() WHERE mobile=%s",
                    (new_level, mobile))
                return new_level

    @staticmethod
    def bind_referrer(mobile: str, referrer_mobile: str):
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur, "users", where_clause="mobile=%s", select_fields=["id"])
                cur.execute(select_sql, (mobile,))
                u = cur.fetchone()
                if not u:
                    raise ValueError("被推荐人不存在")
                cur.execute(select_sql, (referrer_mobile,))
                ref = cur.fetchone()
                if not ref:
                    raise ValueError("推荐人不存在")
                cur.execute(
                    "INSERT INTO user_referrals(user_id, referrer_id) VALUES (%s,%s) "
                    "ON DUPLICATE KEY UPDATE referrer_id=%s",
                    (u["id"], ref["id"], ref["id"])
                )

    @staticmethod
    def set_level(mobile: str, new_level: int, reason: str = "后台手动调整"):
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur, "users", where_clause="mobile=%s",
                    select_fields=["id", "member_level"])
                cur.execute(select_sql, (mobile,))
                row = cur.fetchone()
                if not row:
                    raise ValueError("用户不存在")
                old_level = row["member_level"]
                if old_level == new_level:
                    return old_level
                cur.execute(
                    "UPDATE users SET member_level=%s, level_changed_at=NOW() WHERE mobile=%s",
                    (new_level, mobile))
                conn.commit()
                return new_level

    @staticmethod
    def grant_merchant(mobile: str) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SHOW COLUMNS FROM users LIKE 'is_merchant'")
                if not cur.fetchone():
                    try:
                        cur.execute(
                            "ALTER TABLE users ADD COLUMN is_merchant TINYINT(1) NOT NULL DEFAULT 0")
                        conn.commit()
                    except Exception:
                        return False
                cur.execute("UPDATE users SET is_merchant=1 WHERE mobile=%s", (mobile,))
                conn.commit()
                return cur.rowcount > 0

    @staticmethod
    def is_merchant(mobile: str) -> bool:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SHOW COLUMNS FROM users LIKE 'is_merchant'")
                if not cur.fetchone():
                    return False
                select_sql = build_dynamic_select(
                    cur, "users", where_clause="mobile=%s", select_fields=["is_merchant"])
                cur.execute(select_sql, (mobile,))
                row = cur.fetchone()
                return bool(row and row.get('is_merchant'))

    @staticmethod
    def set_status(mobile: str, new_status: UserStatus, reason: str = "后台调整") -> bool:
        if new_status not in (UserStatus.NORMAL, UserStatus.FROZEN, UserStatus.DELETED):
            raise ValueError("非法状态值")
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur, "users", where_clause="mobile=%s",
                    select_fields=["id", "status"])
                cur.execute(select_sql, (mobile,))
                row = cur.fetchone()
                if not row:
                    raise ValueError("用户不存在")
                old_status = row["status"]
                if old_status == int(new_status):
                    return False
                cur.execute(
                    "UPDATE users SET status=%s WHERE mobile=%s",
                    (int(new_status), mobile))
                conn.commit()
                return cur.rowcount > 0

    @staticmethod
    def promote_unilevel(user_id: int, level: int) -> int:
        from core.config import UnilevelLevel
        if level not in {1, 2, 3}:
            raise ValueError("联创等级只能是 1-3")
        if not UserService._check_unilevel_rules(user_id, level):
            raise ValueError("晋升条件未达标")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO user_unilevel(user_id, level) VALUES (%s,%s) "
                    "ON DUPLICATE KEY UPDATE level=%s",
                    (user_id, level, level),
                )
                conn.commit()
                return level

    @staticmethod
    def get_unilevel(user_id: int) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT level FROM user_unilevel WHERE user_id=%s", (user_id,))
                row = cur.fetchone()
                return row["level"] if row else 0

    # ---------- 私有校验 ----------
    @staticmethod
    def _check_unilevel_rules(uid: int, target: int) -> bool:
        """最新规则：前 N 条直推线各存在 1 个【直推≥3六星】的六星"""
        if UserService.get_level(uid) != 6:
            return False
        direct = UserService._count_direct_6star(uid)
        need = {1: 3, 2: 5, 3: 7}[target]
        if direct < need:
            print(f"直推六星不足：需要 {need}，实际 {direct}")
            return False
        with get_conn() as conn:
            with conn.cursor() as cur:
                return UserService._top_n_lines_have_6star_with_3direct_dynamic(cur, uid, need)

    @staticmethod
    def _count_direct_6star(uid: int) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) AS c FROM user_referrals r "
                    "JOIN users u ON u.id=r.user_id "
                    "WHERE r.referrer_id=%s AND u.member_level=6",
                    (uid,),
                )
                return cur.fetchone()["c"]

    @staticmethod
    def get_level(user_id: int) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT member_level FROM users WHERE id=%s", (user_id,))
                row = cur.fetchone()
                return row["member_level"] if row else 0

    @staticmethod
    def _top_n_lines_have_6star_with_3direct_dynamic(cur, uid: int, n: int) -> bool:
        """动态版：前 n 条直推线各存在≥1 个【直推≥3六星】的六星"""
        cur.execute(
            "SELECT user_id FROM user_referrals WHERE referrer_id=%s ORDER BY id LIMIT %s",
            (uid, n),
        )
        lines = [r["user_id"] for r in cur.fetchall()]
        if len(lines) < n:
            return False
        for top_id in lines:
            cur.execute(
                """
                WITH RECURSIVE team AS (
                    SELECT %s AS id
                    UNION ALL
                    SELECT r.user_id
                    FROM user_referrals r
                    JOIN team t ON t.id=r.referrer_id
                )
                SELECT 1
                FROM team
                JOIN users u ON u.id=team.id
                WHERE u.member_level=6
                  AND (SELECT COUNT(*)
                       FROM user_referrals r2
                       JOIN users u2 ON u2.id=r2.user_id
                       WHERE r2.referrer_id=team.id
                         AND u2.member_level=6) >= 3
                LIMIT 1
                """,
                (top_id,),
            )
            if not cur.fetchone():
                return False
        return True