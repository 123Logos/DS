import uuid
import bcrypt
from typing import Optional, Dict, Any
from enum import IntEnum
from core.database import get_conn
from core.table_access import build_dynamic_select, _quote_identifier
import string
import random
import os
from core.config import AVATAR_UPLOAD_DIR
from fastapi import UploadFile, HTTPException
from typing import List
from pathlib import Path
from PIL import Image
import json



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
    def get_unilevel(user_id: int) -> int:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT level FROM user_unilevel WHERE user_id=%s", (user_id,))
                row = cur.fetchone()
                return row["level"] if row else 0



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
    def upload_avatar(user_id: int, files: List[UploadFile]) -> List[str]:
        """
        行为与 upload_product_images 完全一致：
        1. 支持多张（≤3）
        2. 单张 ≤2MB
        3. 统一压缩、重命名、返回 URL 数组
        4. 留空则清空头像
        """
        if len(files) > 3:
            raise HTTPException(status_code=400, detail="头像最多3张")

        urls = []
        for f in files:
            if f.size > 2 * 1024 * 1024:
                raise HTTPException(status_code=400, detail="单张头像不能超过2MB")
            ext = Path(f.filename).suffix.lower()
            if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                raise HTTPException(status_code=400, detail="仅支持 JPG/PNG/WEBP")

            name = f"avatar_{user_id}_{uuid.uuid4().hex}{ext}"
            path = AVATAR_UPLOAD_DIR / name
            path.parent.mkdir(parents=True, exist_ok=True)

            with Image.open(f.file) as im:
                im = im.convert("RGB")
                im.thumbnail((300, 300), Image.LANCZOS)  # 头像统一 300×300
                im.save(path, "JPEG", quality=85, optimize=True)

            urls.append(f"/pic/avatars/{name}")

        # 写库（仿照商品图更新 main_image）
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE users SET avatar_path = %s, updated_at = NOW() WHERE id = %s",
                    (json.dumps(urls, ensure_ascii=False), user_id)
                )
                conn.commit()

        return urls

    # ==================== 优惠券查询功能 ====================

    def query_user_coupons(self, user_id: int, status: str = 'all',
                           page: int = 1, page_size: int = 20) -> dict:
        """查询指定用户的优惠券"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 不使用表别名
                where = ["user_id = %s"]
                params = [user_id]

                if status != 'all':
                    if status == 'expired':
                        where.append("status = 'unused' AND valid_to < CURDATE()")
                    else:
                        where.append("status = %s")
                        params.append(status)

                # 查询总数
                where_clause = " AND ".join(where)
                count_sql = f"SELECT COUNT(*) as total FROM coupons WHERE {where_clause}"
                cur.execute(count_sql, tuple(params))
                total = cur.fetchone()['total'] or 0

                # 查询明细
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT id, coupon_type, amount, status, valid_from, valid_to,
                           used_at, created_at
                    FROM coupons
                    WHERE {where_clause}
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                coupons = cur.fetchall()

                return {
                    "coupons": [dict(c) for c in coupons],
                    "total": total,
                    "page": page,
                    "page_size": page_size
                }

    # ==================== 联创自动计算功能（后端计算） ====================

    @staticmethod
    def get_unilevel_status(user_id: int) -> Dict[str, Any]:
        """
        获取联创状态（等级+是否可晋升）
        前端直接调用此方法获取完整信息
        """
        try:
            current_level = UserService.get_unilevel(user_id)
            target_level = UserService._calculate_unilevel_target(user_id)

            return {
                "current_level": current_level,
                "target_level": target_level,
                "can_promote": target_level > current_level,
                "reason": None if target_level > current_level else "已到达最高等级或条件未达标"
            }
        except Exception as e:
            print(f"获取联创状态失败: {e}")
            return {
                "current_level": 0,
                "target_level": 0,
                "can_promote": False,
                "reason": str(e)
            }

    @staticmethod
    def _calculate_unilevel_target(uid: int) -> int:
        """
        计算用户应得的联创等级（核心逻辑）
        返回值：0=未获得, 1=一星, 2=二星, 3=三星
        """
        if UserService.get_level(uid) != 6:
            return 0

        # 获取前7条直推线（按注册顺序）
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT user_id FROM user_referrals "
                    "WHERE referrer_id=%s ORDER BY created_at LIMIT 7",
                    (uid,),
                )
                lines = [r["user_id"] for r in cur.fetchall()]

                # 统计每条线是否满足条件（用单SQL优化）
                valid_lines = UserService._count_valid_lines(cur, lines)

                # 正确的业务逻辑：满足条件的线数 ≥ 要求线数
                if valid_lines >= 7:
                    return 3  # 联创三星
                elif valid_lines >= 5:
                    return 2  # 联创二星
                elif valid_lines >= 3:
                    return 1  # 联创一星

        return 0

    @staticmethod
    def _count_valid_lines(cur, line_ids: List[int]) -> int:
        """
        核心优化：一次性查出所有直推线中有多少条满足条件
        解决N+1问题（兼容MySQL 5.7+）
        """
        if not line_ids:
            return 0

        # 使用UNION ALL构造临时表（兼容所有MySQL版本）
        union_parts = " UNION ALL ".join([f"SELECT {uid} as user_id" for uid in line_ids])

        cur.execute(
            f"""
            WITH RECURSIVE all_teams AS (
                -- 使用UNION ALL构造临时表
                SELECT user_id AS id, user_id AS root_id, 1 as level
                FROM ({union_parts}) AS roots
                UNION ALL
                SELECT r.user_id, at.root_id, at.level + 1
                FROM user_referrals r
                JOIN all_teams at ON at.id = r.referrer_id
                WHERE at.level < 6  -- 限制递归深度
            ),
            line_stats AS (
                SELECT 
                    root_id,
                    EXISTS (
                        SELECT 1
                        FROM all_teams at2
                        JOIN users u ON u.id = at2.id
                        WHERE at2.root_id = at.root_id
                          AND u.member_level = 6
                          AND (
                              SELECT COUNT(DISTINCT r2.user_id)
                              FROM user_referrals r2
                              JOIN users u2 ON u2.id = r2.user_id
                              WHERE r2.referrer_id = at2.id
                                AND u2.member_level = 6
                          ) >= 3
                    ) as has_valid_6star
                FROM (SELECT DISTINCT root_id FROM all_teams) at
            )
            SELECT COUNT(*) as valid_count
            FROM line_stats
            WHERE has_valid_6star = TRUE
            """
        )
        return cur.fetchone()['valid_count'] or 0

    @staticmethod
    def promote_unilevel_auto(user_id: int) -> int:
        """自动晋升联创（后端计算）"""
        status = UserService.get_unilevel_status(user_id)

        if not status["can_promote"]:
            raise ValueError(f"无法晋升：{status['reason']}")

        target_level = status["target_level"]

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO user_unilevel(user_id, level) VALUES (%s,%s) "
                    "ON DUPLICATE KEY UPDATE level=%s",
                    (user_id, target_level, target_level),
                )
                conn.commit()
                return target_level

    '''
    @staticmethod
    def get_user_special_points(user_id: int) -> Dict[str, float]:
        """
        查询用户团队奖励和推荐奖励专用点数

        返回字段：
        - team_reward_points: 团队奖励专用点数
        - referral_points: 推荐奖励专用点数
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 直接查询两个字段，避免不必要的字段检查
                cur.execute(
                    """
                    SELECT 
                        COALESCE(team_reward_points, 0) as team_reward_points,
                        COALESCE(referral_points, 0) as referral_points
                    FROM users
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                row = cur.fetchone()

                if not row:
                    raise ValueError("用户不存在")

                return {
                    "team_reward_points": float(row['team_reward_points']),
                    "referral_points": float(row['referral_points'])
                }

    @staticmethod
    def get_user_subsidy_points(user_id: int) -> Dict[str, float]:
        """
        查询用户周补贴专用点数
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 直接查询周补贴专用点数
                cur.execute(
                    """
                    SELECT COALESCE(subsidy_points, 0) as subsidy_points
                    FROM users
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                row = cur.fetchone()

                if not row:
                    raise ValueError("用户不存在")

                return {
                    "subsidy_points": float(row['subsidy_points'])
                }

    @staticmethod
    def get_user_unilevel_points(user_id: int) -> Dict[str, float]:
        """
        查询用户联创星级专用点数
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 直接查询points字段（联创星级专用点数）
                cur.execute(
                    """
                    SELECT COALESCE(points, 0) as unilevel_points
                    FROM users
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                row = cur.fetchone()

                if not row:
                    raise ValueError("用户不存在")

                return {
                    "unilevel_points": float(row['unilevel_points'])
                }
'''
    @staticmethod
    def get_user_all_points(user_id: int) -> Dict[str, float]:
        """
        查询用户所有专用点数及总和

        返回四个点数字段的值及其总和：
        - unilevel_points: 联创星级专用点数
        - subsidy_points: 周补贴专用点数
        - team_reward_points: 团队奖励专用点数
        - referral_points: 推荐奖励专用点数
        - total_points: 四个点数总和
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 直接查询四个点数字段
                cur.execute(
                    """
                    SELECT 
                        COALESCE(points, 0) as unilevel_points,
                        COALESCE(subsidy_points, 0) as subsidy_points,
                        COALESCE(team_reward_points, 0) as team_reward_points,
                        COALESCE(referral_points, 0) as referral_points
                    FROM users
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                row = cur.fetchone()

                if not row:
                    raise ValueError("用户不存在")

                # 计算总和
                total = (
                        float(row['unilevel_points']) +
                        float(row['subsidy_points']) +
                        float(row['team_reward_points']) +
                        float(row['referral_points'])
                )

                return {
                    "unilevel_points": float(row['unilevel_points']),
                    "subsidy_points": float(row['subsidy_points']),
                    "team_reward_points": float(row['team_reward_points']),
                    "referral_points": float(row['referral_points']),
                    "total_points": total
                }

    '''
    @staticmethod
    def clear_reward_points(user_id: int, reason: str = "后台清除") -> Dict[str, Any]:
        """
        一键清除用户的团队奖励和推荐奖励专用点数

        参数:
            user_id: 用户ID
            reason: 操作原因（返回提示用）

        返回:
            dict: 包含清除前后的点数信息
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 检查用户是否存在并获取当前点数
                cur.execute(
                    """
                    SELECT 
                        COALESCE(team_reward_points, 0) as team_reward_points,
                        COALESCE(referral_points, 0) as referral_points
                    FROM users
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                row = cur.fetchone()
                if not row:
                    raise ValueError("用户不存在")

                # 2. 记录清除前的点数
                old_team_points = float(row['team_reward_points'])
                old_referral_points = float(row['referral_points'])

                # 3. 如果已经是0，无需操作
                if old_team_points == 0 and old_referral_points == 0:
                    return {
                        "cleared": False,
                        "message": "点数已为0，无需清除",
                        "old_team_points": old_team_points,
                        "old_referral_points": old_referral_points,
                        "new_team_points": 0,
                        "new_referral_points": 0
                    }

                # 4. 执行清除操作（设置为0）
                cur.execute(
                    """
                    UPDATE users 
                    SET team_reward_points = 0, 
                        referral_points = 0,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                conn.commit()

                return {
                    "cleared": True,
                    "message": f"奖励点数已清除（原因：{reason}）",
                    "old_team_points": old_team_points,
                    "old_referral_points": old_referral_points,
                    "new_team_points": 0,
                    "new_referral_points": 0
                }

    @staticmethod
    def clear_subsidy_points(user_id: int, reason: str = "后台清除") -> Dict[str, Any]:
        """
        一键清除用户的周补贴专用点数

        参数:
            user_id: 用户ID
            reason: 操作原因（返回提示用）

        返回:
            dict: 包含清除前后的点数信息
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 检查用户是否存在并获取当前点数
                cur.execute(
                    """
                    SELECT 
                        COALESCE(subsidy_points, 0) as subsidy_points
                    FROM users
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                row = cur.fetchone()
                if not row:
                    raise ValueError("用户不存在")

                # 2. 记录清除前的点数
                old_points = float(row['subsidy_points'])

                # 3. 如果已经是0，无需操作
                if old_points == 0:
                    return {
                        "cleared": False,
                        "message": "周补贴点数已为0，无需清除",
                        "old_subsidy_points": old_points,
                        "new_subsidy_points": 0
                    }

                # 4. 执行清除操作（设置为0）
                cur.execute(
                    """
                    UPDATE users 
                    SET subsidy_points = 0,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                conn.commit()

                return {
                    "cleared": True,
                    "message": f"周补贴点数已清除（原因：{reason}）",
                    "old_subsidy_points": old_points,
                    "new_subsidy_points": 0
                }

    @staticmethod
    def clear_unilevel_points(user_id: int, reason: str = "后台清除") -> Dict[str, Any]:
        """
        一键清除用户的联创星级专用点数

        参数:
            user_id: 用户ID
            reason: 操作原因（返回提示用）

        返回:
            dict: 包含清除前后的点数信息
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 检查用户是否存在并获取当前点数
                cur.execute(
                    """
                    SELECT 
                        COALESCE(points, 0) as unilevel_points
                    FROM users
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                row = cur.fetchone()
                if not row:
                    raise ValueError("用户不存在")

                # 2. 记录清除前的点数
                old_points = float(row['unilevel_points'])

                # 3. 如果已经是0，无需操作
                if old_points == 0:
                    return {
                        "cleared": False,
                        "message": "联创星级点数已为0，无需清除",
                        "old_unilevel_points": old_points,
                        "new_unilevel_points": 0
                    }

                # 4. 执行清除操作（设置为0）
                cur.execute(
                    """
                    UPDATE users 
                    SET points = 0,
                        updated_at = NOW()
                    WHERE id = %s
                    """,
                    (user_id,)
                )

                conn.commit()

                return {
                    "cleared": True,
                    "message": f"联创星级点数已清除（原因：{reason}）",
                    "old_unilevel_points": old_points,
                    "new_unilevel_points": 0
                }
'''
    @staticmethod
    def get_points_summary(user_id: int) -> Dict[str, float]:
        """
        查询用户点数汇总信息

        业务定义：
        - 四个专用点数：各渠道累计获得的点数
        - true_total_points：剩余可用点数
        - 累计总值 = 四个专用点数之和
        - 已使用点数 = 累计总值 - 剩余点数
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 动态获取表结构
                cur.execute("SHOW COLUMNS FROM users")
                user_cols = [r["Field"] for r in cur.fetchall()]

                # 基础查询字段（四个点数）
                select_fields = [
                    "COALESCE(points, 0) as unilevel_points",
                    "COALESCE(subsidy_points, 0) as subsidy_points",
                    "COALESCE(team_reward_points, 0) as team_reward_points",
                    "COALESCE(referral_points, 0) as referral_points"
                ]

                # 检查是否存在 true_total_points 字段
                has_true_total = "true_total_points" in user_cols
                if has_true_total:
                    select_fields.append("COALESCE(true_total_points, 0) as true_total_points")

                # 执行查询
                sql = f"""
                    SELECT {', '.join(select_fields)}
                    FROM users
                    WHERE id = %s
                """
                cur.execute(sql, (user_id,))
                row = cur.fetchone()

                if not row:
                    raise ValueError("用户不存在")

                # 计算四个点数的累计总值
                unilevel = float(row['unilevel_points'])
                subsidy = float(row['subsidy_points'])
                team = float(row['team_reward_points'])
                referral = float(row['referral_points'])
                cumulative_total = unilevel + subsidy + team + referral

                # 剩余点数直接读取 true_total_points
                if has_true_total:
                    remaining_points = float(row['true_total_points'])
                else:
                    remaining_points = 0.0

                # 计算已使用点数
                used_points = cumulative_total - remaining_points

                return {
                    "unilevel_points": unilevel,
                    "subsidy_points": subsidy,
                    "team_reward_points": team,
                    "referral_points": referral,
                    "cumulative_total": cumulative_total,
                    "remaining_points": remaining_points,
                    "used_points": used_points
                }

    @staticmethod
    def set_unilevel(user_id: int, level: int) -> Dict[str, Any]:
        """
        后台设置用户的联创星级（不包含updated_at字段）
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 检查用户是否存在
                cur.execute("SELECT 1 FROM users WHERE id = %s", (user_id,))
                if not cur.fetchone():
                    raise ValueError("用户不存在")

                # 2. 检查表是否存在，不存在则创建（简化结构）
                cur.execute("SHOW TABLES LIKE 'user_unilevel'")
                if not cur.fetchone():
                    cur.execute("""
                        CREATE TABLE user_unilevel (
                            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                            user_id BIGINT UNSIGNED NOT NULL UNIQUE,
                            level TINYINT NOT NULL DEFAULT 0,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                            KEY idx_user_id (user_id)
                        )
                    """)
                    conn.commit()

                # 3. 获取旧等级
                cur.execute("SELECT level FROM user_unilevel WHERE user_id = %s", (user_id,))
                old_row = cur.fetchone()
                old_level = old_row["level"] if old_row else 0

                # 4. 幂等检查
                if old_level == level:
                    return {
                        "user_id": user_id,
                        "old_level": old_level,
                        "new_level": level,
                        "changed": False,
                        "message": "等级未变化"
                    }

                # 5. 更新或插入（无需updated_at）
                cur.execute(
                    """
                    INSERT INTO user_unilevel (user_id, level) 
                    VALUES (%s, %s)
                    ON DUPLICATE KEY UPDATE level = %s
                    """,
                    (user_id, level, level)
                )

                conn.commit()

                return {
                    "user_id": user_id,
                    "old_level": old_level,
                    "new_level": level,
                    "changed": True,
                    "message": "联创星级已更新"
                }