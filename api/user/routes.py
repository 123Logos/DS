from fastapi import HTTPException, APIRouter, Request
import uuid
import datetime

from models.schemas.user import (
    SetStatusReq, AuthReq, AuthResp, UpdateProfileReq, SelfDeleteReq,
    FreezeReq, ResetPwdReq, AdminResetPwdReq, SetLevelReq, AddressReq,
    PointsReq, UserInfoResp
)

from core.database import get_conn
from core.logging import get_logger
from core.table_access import build_dynamic_select, get_table_structure
from services.user_service import UserService, UserStatus, verify_pwd, hash_pwd
from services.address_service import AddressService
from services.points_service import add_points
from services.reward_service import TeamRewardService
from services.director_service import DirectorService
from services.wechat_service import WechatService

logger = get_logger(__name__)


def _err(msg: str):
    raise HTTPException(status_code=400, detail=msg)


# 创建用户中心路由
router = APIRouter()


def register_routes(app):
    """注册用户中心路由到主应用"""
    # 将所有路由从 app 改为 router
    # 然后统一注册时添加 tags
    app.include_router(router, tags=["用户中心"])


# 将所有路由从 @app. 改为 @router.
@router.post("/user/set-status", summary="冻结/注销/恢复正常（动态字段/自动建表）")
def set_user_status(body: SetStatusReq):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 若 users 表无 status 字段，自动添加
            cur.execute("SHOW COLUMNS FROM users")
            user_cols = [r["Field"] for r in cur.fetchall()]
            if "status" not in user_cols:
                cur.execute(
                    "ALTER TABLE users ADD COLUMN status TINYINT NOT NULL DEFAULT 0 COMMENT '0-正常 1-冻结 2-注销'"
                )
                conn.commit()

            # 2. 校验用户是否存在
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "status"]
            )
            cur.execute(select_sql, (body.mobile,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="用户不存在")
            user_id, old_status = row["id"], row["status"]

            new_status_int = int(body.new_status)
            if old_status == new_status_int:
                return {"success": False}          # 无变化

            # 3. 更新用户状态
            cur.execute(
                "UPDATE users SET status=%s WHERE mobile=%s",
                (new_status_int, body.mobile)
            )
            conn.commit()

            # 4. 审计日志（表不存在则自动创建）
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    old_val INT NOT NULL,
                    new_val INT NOT NULL,
                    reason VARCHAR(200),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute(
                "INSERT INTO audit_log (user_id, old_val, new_val, reason) VALUES (%s,%s,%s,%s)",
                (user_id, old_status, new_status_int, body.reason)
            )
            conn.commit()
            return {"success": True}

@router.post("/user/auth", summary="一键登录（不存在则自动注册）")
def user_auth(body: AuthReq):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "password_hash", "member_level", "status"]
            )
            cur.execute(select_sql, (body.mobile,))
            row = cur.fetchone()

            if row:
                if not verify_pwd(body.password, row["password_hash"]):
                    raise HTTPException(status_code=400, detail="手机号或密码错误")
                status = row["status"]
                if status == UserStatus.FROZEN:
                    raise HTTPException(status_code=403, detail="账号已冻结")
                if status == UserStatus.DELETED:
                    raise HTTPException(status_code=403, detail="账号已注销")
                token = str(uuid.uuid4())
                return AuthResp(uid=row["id"], token=token, level=row["member_level"], is_new=False)

            try:
                uid = UserService.register(
                    mobile=body.mobile,
                    pwd=body.password,
                    name=body.name,
                    referrer_mobile=None
                )
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

            token = str(uuid.uuid4())
            return AuthResp(uid=uid, token=token, level=0, is_new=True)

@router.post("/user/update-profile", summary="修改资料（动态字段/兼容老库）")
def update_profile(body: UpdateProfileReq):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 取用户 id & 当前密码哈希
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "password_hash"]
            )
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            user_id, old_hash = u["id"], u["password_hash"]

            # 2. 嗅探真实字段
            cur.execute("SHOW COLUMNS FROM users")
            cols = [r["Field"] for r in cur.fetchall()]

            # 3. 准备待更新字典
            updates = {}
            if "name" in cols and body.name is not None:
                updates["name"] = body.name
            if "avatar_path" in cols and body.avatar_path is not None:
                updates["avatar_path"] = body.avatar_path

            # 4. 密码单独处理（需校验旧密码）
            if body.new_password is not None:
                if not body.old_password:
                    raise HTTPException(status_code=400, detail="请提供旧密码")
                if not verify_pwd(body.old_password, old_hash):
                    raise HTTPException(status_code=400, detail="旧密码错误")
                if "password_hash" in cols:
                    updates["password_hash"] = hash_pwd(body.new_password)

            # 5. 若无更新直接返回
            if not updates:
                return {"msg": "无字段需要更新"}

            # 6. 动态构造 SET 子句
            set_clause = ", ".join([f"{k}=%s" for k in updates])
            sql = f"UPDATE users SET {set_clause} WHERE id=%s"
            cur.execute(sql, tuple(updates.values()) + (user_id,))
            conn.commit()
            return {"msg": "ok"}

@router.post("/user/self-delete", summary="用户自助注销（动态字段/兼容老库）")
def self_delete(body: SelfDeleteReq):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 若 users 表无 status 字段，自动添加
            cur.execute("SHOW COLUMNS FROM users")
            user_cols = [r["Field"] for r in cur.fetchall()]
            if "status" not in user_cols:
                cur.execute(
                    "ALTER TABLE users ADD COLUMN status TINYINT NOT NULL DEFAULT 0 COMMENT '0-正常 1-冻结 2-注销'"
                )
                conn.commit()

            # 2. 取用户 id & 密码哈希
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "password_hash", "status"]
            )
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            user_id, db_hash, old_status = u["id"], u["password_hash"], u["status"]

            # 3. 校验密码
            if not verify_pwd(body.password, db_hash):
                raise HTTPException(status_code=403, detail="密码错误")

            # 4. 幂等：已注销直接返回
            if old_status == int(UserStatus.DELETED):
                return {"msg": "账号已注销"}

            # 5. 更新状态
            cur.execute("UPDATE users SET status=%s WHERE id=%s", (int(UserStatus.DELETED), user_id))

            # 6. 审计日志（表不存在则自动创建）
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    old_val INT NOT NULL,
                    new_val INT NOT NULL,
                    reason VARCHAR(200),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute(
                "INSERT INTO audit_log (user_id, old_val, new_val, reason) VALUES (%s,%s,%s,%s)",
                (user_id, old_status, int(UserStatus.DELETED), body.reason)
            )
            conn.commit()
            return {"msg": "账号已注销"}

@router.put("/user/freeze", summary="后台冻结用户")
def freeze_user(body: FreezeReq):
    if body.admin_key != "admin2025":
        raise HTTPException(status_code=403, detail="后台口令错误")

    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "status"]
            )
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            if u["status"] == UserStatus.DELETED:
                raise HTTPException(status_code=400, detail="账号已注销，无法冻结")

            new_status = UserStatus.FROZEN.value
            if u["status"] == new_status:
                return {"msg": "已是冻结状态"}

            cur.execute("UPDATE users SET status=%s WHERE id=%s", (new_status, u["id"]))
            conn.commit()
    return {"msg": "已冻结"}

@router.put("/user/unfreeze", summary="后台解冻用户")
def unfreeze_user(body: FreezeReq):
    if body.admin_key != "admin2025":
        raise HTTPException(status_code=403, detail="后台口令错误")

    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "status"]
            )
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")

            new_status = UserStatus.NORMAL.value
            if u["status"] == new_status:
                return {"msg": "已是正常状态"}

            cur.execute("UPDATE users SET status=%s WHERE id=%s", (new_status, u["id"]))
            conn.commit()
    return {"msg": "已解冻"}

@router.post("/user/reset-password", summary="找回密码（短信验证）")
def reset_password(body: ResetPwdReq):
    if body.sms_code != "111111":
        raise HTTPException(status_code=400, detail="验证码错误")

    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="手机号未注册")

            new_hash = hash_pwd(body.new_password)
            cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (new_hash, u["id"]))
            conn.commit()
    return {"msg": "密码已重置"}

@router.put("/admin/user/reset-pwd", summary="后台重置用户密码")
def admin_reset_password(body: AdminResetPwdReq):
    if body.admin_key != "admin2025":
        raise HTTPException(status_code=403, detail="后台口令错误")

    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")

            new_hash = hash_pwd(body.new_password)
            cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (new_hash, u["id"]))
            conn.commit()
    return {"msg": "密码已重置"}

@router.post("/user/upgrade", summary="升 1 星（动态字段/兼容老库）")
def upgrade(mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 自动加字段
            cur.execute("SHOW COLUMNS FROM users")
            cols = [r["Field"] for r in cur.fetchall()]
            if "member_level" not in cols:
                cur.execute(
                    "ALTER TABLE users ADD COLUMN member_level TINYINT NOT NULL DEFAULT 0 COMMENT '0-6 星'"
                )
                conn.commit()

            # 2. 取当前星级
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "member_level"]
            )
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            user_id, old_level = u["id"], u["member_level"]
            if old_level >= 6:
                raise HTTPException(status_code=400, detail="已是最高星级（6星）")
            new_level = old_level + 1

            # 3. 动态 SET 子句（NOW() 不占位）
            set_parts = []
            args = []
            set_parts.append("member_level=%s")
            args.append(new_level)
            if "level_changed_at" in cols:
                set_parts.append("level_changed_at=NOW()")
            sql = f"UPDATE users SET {', '.join(set_parts)} WHERE id=%s"
            args.append(user_id)          # 最后一个占位符
            cur.execute(sql, tuple(args)) # 参数数量 = 占位符数量

            # 4. 审计日志
            cur.execute("""CREATE TABLE IF NOT EXISTS audit_log (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                old_val INT NOT NULL,
                new_val INT NOT NULL,
                reason VARCHAR(200),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP)""")
            cur.execute(
                "INSERT INTO audit_log (user_id, old_val, new_val, reason) VALUES (%s,%s,%s,%s)",
                (user_id, old_level, new_level, "用户升级一星"))
            conn.commit()
            return {"new_level": new_level}

@router.post("/user/set-level", summary="后台调星（动态字段/兼容老库）")
def set_level(body: SetLevelReq):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 若 users 表无 member_level 字段，自动添加
            cur.execute("SHOW COLUMNS FROM users")
            user_cols = [r["Field"] for r in cur.fetchall()]
            if "member_level" not in user_cols:
                cur.execute(
                    "ALTER TABLE users ADD COLUMN member_level TINYINT NOT NULL DEFAULT 0 COMMENT '0-6 星'"
                )
                conn.commit()

            # 2. 取当前星级
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "member_level"]
            )
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            user_id, old_level = u["id"], u["member_level"]

            # 3. 区间 & 幂等校验
            if not (0 <= body.new_level <= 6):
                raise HTTPException(status_code=400, detail="星级必须在 0~6 之间")
            if old_level == body.new_level:
                return {"old_level": old_level, "new_level": old_level}  # 无变化

            # 4. 动态构造更新子句
            updates = {"member_level": body.new_level}
            if "level_changed_at" in user_cols:
                updates["level_changed_at"] = "NOW()"   # SQL 函数特殊处理

            set_clause = ", ".join([f"{k}=NOW()" if v == "NOW()" else f"{k}=%s" for k, v in updates.items()])
            sql = f"UPDATE users SET {set_clause} WHERE id=%s"
            vals = [v for v in updates.values() if v != "NOW()"] + [user_id]
            cur.execute(sql, tuple(vals))

            # 5. 审计日志（表不存在则自动创建）
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    old_val INT NOT NULL,
                    new_val INT NOT NULL,
                    reason VARCHAR(200),
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute(
                "INSERT INTO audit_log (user_id, old_val, new_val, reason) VALUES (%s,%s,%s,%s)",
                (user_id, old_level, body.new_level, body.reason)
            )
            conn.commit()
            return {"old_level": old_level, "new_level": body.new_level}

@router.get("/user/info", summary="用户详情（个人中心）", response_model=UserInfoResp)
def user_info(mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT id, mobile, name, avatar_path, member_level, referral_code "
                "FROM users WHERE mobile=%s AND status != %s",
                (mobile, UserStatus.DELETED.value)
            )
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在或已注销")

            cur.execute(
                "SELECT ru.mobile, ru.name, ru.member_level "
                "FROM user_referrals r JOIN users ru ON ru.id=r.referrer_id "
                "WHERE r.user_id=%s",
                (u["id"],)
            )
            referrer = cur.fetchone()

            cur.execute(
                "SELECT COUNT(*) AS c FROM user_referrals WHERE referrer_id=%s",
                (u["id"],)
            )
            direct_count = cur.fetchone()["c"]

            cur.execute(
                """
                WITH RECURSIVE team AS (
                    SELECT id, 0 AS layer FROM users WHERE id=%s
                    UNION ALL
                    SELECT r.user_id, t.layer + 1
                    FROM user_referrals r
                    JOIN team t ON t.id = r.referrer_id
                    WHERE t.layer < 6
                )
                SELECT COUNT(*) - 1 AS c FROM team
                """,
                (u["id"],)
            )
            team_total = cur.fetchone()["c"]

            # 使用动态 SELECT 查询积分和余额字段
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="id=%s",
                select_fields=["member_points", "merchant_points", "withdrawable_balance"]
            )
            cur.execute(select_sql, (u["id"],))
            assets = cur.fetchone()

    return UserInfoResp(
        uid=u["id"],
        mobile=u["mobile"],
        name=u["name"],
        avatar_path=u["avatar_path"],
        member_level=u["member_level"],
        referral_code=u["referral_code"],
        direct_count=direct_count,
        team_total=team_total,
        assets={
            "member_points": assets.get("member_points", 0) or 0,
            "merchant_points": assets.get("merchant_points", 0) or 0,
            "withdrawable_balance": assets.get("withdrawable_balance", 0) or 0
        },
        referrer=referrer
    )

@router.get("/user/list", summary="分页列表+筛选")
def user_list(
    id_start: int = None,
    id_end: int = None,
    level_start: int = 0,
    level_end: int = 6,
    page: int = 1,
    size: int = 20,
):
    if level_start > level_end or (id_start is not None and id_end is not None and id_start > id_end):
        _err("区间左值不能大于右值")
    where, args = [], []
    if id_start is not None:
        where.append("id >= %s")
        args.append(id_start)
    if id_end is not None:
        where.append("id <= %s")
        args.append(id_end)
    where.append("member_level BETWEEN %s AND %s")
    args.extend([level_start, level_end])
    sql_where = "WHERE " + " AND ".join(where) if where else ""
    limit_sql = "LIMIT %s OFFSET %s"
    args.extend([size, (page - 1) * size])
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 使用动态表访问构造查询
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause=sql_where.replace("WHERE ", "") if sql_where else None,
                order_by="id",
                limit=limit_sql.replace("LIMIT ", "") if limit_sql else None,
                select_fields=["id", "mobile", "name", "member_level", "created_at"]
            )
            cur.execute(select_sql, tuple(args))
            rows = cur.fetchall()
            # COUNT 查询
            count_sql = f"SELECT COUNT(*) AS c FROM users {sql_where}"
            cur.execute(count_sql, tuple(args[:-2]))
            total = cur.fetchone()["c"]
            return {"rows": rows, "total": total, "page": page, "size": size}

@router.post("/user/bind-referrer", summary="绑定推荐人（动态字段/自动建表）")
def bind_referrer(mobile: str, referrer_mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 被推荐人 & 推荐人 id
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="被推荐人不存在")
            user_id = u["id"]

            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (referrer_mobile,))
            ref = cur.fetchone()
            if not ref:
                raise HTTPException(status_code=404, detail="推荐人不存在")
            referrer_id = ref["id"]

            # 2. 若 user_referrals 表不存在则自动创建（最简版）
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_referrals (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    referrer_id INT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uk_uid (user_id)
                )
            """)

            # 3. 嗅探真实字段
            cur.execute("SHOW COLUMNS FROM user_referrals")
            cols = [r["Field"] for r in cur.fetchall()]

            # 4. 准备写入字典
            data = {"user_id": user_id, "referrer_id": referrer_id}
            if "created_at" in cols:
                data["created_at"] = "NOW()"   # 特殊处理 SQL 函数

            # 5. 动态构造 SQL
            insert_cols = ",".join(data.keys())
            placeholders = ",".join(["%s" if k != "created_at" else "NOW()" for k in data.keys()])
            updates = ",".join([f"{k}=VALUES({k})" for k in data.keys() if k != "created_at"])
            sql = f"""
                INSERT INTO user_referrals ({insert_cols})
                VALUES ({placeholders})
                ON DUPLICATE KEY UPDATE {updates}
            """
            cur.execute(sql, tuple(v for k, v in data.items() if k != "created_at"))
            conn.commit()
            return {"msg": "ok"}

@router.get("/user/refer-direct", summary="直推列表")
def refer_direct(mobile: str, page: int = 1, size: int = 10):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u:
                _err("用户不存在")
            # COUNT(*) 是聚合函数，不能使用 build_dynamic_select，直接使用 SQL
            cur.execute("SELECT COUNT(*) AS c FROM user_referrals WHERE referrer_id=%s", (u["id"],))
            total = cur.fetchone()["c"]
            cur.execute("""
                SELECT u.id, u.mobile, u.name, u.member_level, u.created_at
                FROM user_referrals r
                JOIN users u ON u.id = r.user_id
                WHERE r.referrer_id=%s
                ORDER BY u.created_at DESC
                LIMIT %s OFFSET %s
            """, (u["id"], size, (page - 1) * size))
            rows = cur.fetchall()
            return {"rows": rows, "total": total, "page": page, "size": size}

@router.get("/user/refer-team", summary="团队列表（递归）")
def refer_team(mobile: str, max_layer: int = 6):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                WITH RECURSIVE team AS (
                    SELECT id, mobile, name, member_level, 0 AS layer FROM users WHERE mobile=%s
                    UNION ALL
                    SELECT u.id, u.mobile, u.name, u.member_level, t.layer + 1
                    FROM user_referrals r
                    JOIN users u ON u.id = r.user_id
                    JOIN team t ON t.id = r.referrer_id
                    WHERE t.layer < %s
                )
                SELECT id, mobile, name, member_level, layer
                FROM team
                WHERE layer > 0
                ORDER BY layer, id
            """, (mobile, max_layer))
            rows = cur.fetchall()
            return {"rows": rows}

# 地址模块
@router.post("/address", summary="新增地址（兼容老表结构）")
def address_add(body: AddressReq):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 取用户 id
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            user_id = u["id"]

            # 2. 嗅探真实字段
            cur.execute("SHOW COLUMNS FROM user_addresses")
            cols = [r["Field"] for r in cur.fetchall()]  # 真实字段名列表

            # 3. 准备待写入字典（键为数据库真实字段）
            data = {
                "user_id": user_id,
                "consignee_name": body.name,
                "consignee_phone": body.phone,
                "province": body.province,
                "city": body.city,
                "district": body.district,
                "detail": body.detail,
                "label": body.label,
                "is_default": body.is_default,
                "addr_type": body.addr_type,
            }
            # 可选坐标字段
            if body.lng is not None:
                data["lng"] = body.lng
            if body.lat is not None:
                data["lat"] = body.lat

            # 4. 过滤掉表不存在的字段
            insert_data = {k: v for k, v in data.items() if k in cols}
            if not insert_data:
                raise RuntimeError("user_addresses 表无可用字段，请检查表结构")

            # 5. 构造动态 SQL
            sql_cols = ",".join(insert_data.keys())
            placeholders = ",".join(["%s"] * len(insert_data))
            sql = f"INSERT INTO user_addresses({sql_cols}) VALUES ({placeholders})"
            cur.execute(sql, tuple(insert_data.values()))
            addr_id = cur.lastrowid

            # 6. 如果新地址设为默认，把同用户其他地址取消默认
            if body.is_default:
                cur.execute(
                    "UPDATE user_addresses SET is_default=0 WHERE user_id=%s AND id!=%s",
                    (user_id, addr_id)
                )
            conn.commit()
            return {"addr_id": addr_id}
@router.put("/address/default", summary="把已有地址设为默认")
def set_default_addr(addr_id: int, mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "user_addresses",
                where_clause="id=%s",
                select_fields=["user_id"]
            )
            cur.execute(select_sql, (addr_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="地址不存在")
            user_id = row["user_id"]
            cur.execute("UPDATE user_addresses SET is_default=0 WHERE user_id=%s", (user_id,))
            cur.execute("UPDATE user_addresses SET is_default=1 WHERE id=%s", (addr_id,))
            conn.commit()
    return {"msg": "ok"}

@router.delete("/address/{addr_id}", summary="删除地址", operation_id="delete_user_address")
def delete_addr(addr_id: int, mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM addresses WHERE id=%s", (addr_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="地址不存在")
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u or u["id"] != row["user_id"]:
                raise HTTPException(status_code=403, detail="地址不属于当前用户")

            cur.execute("DELETE FROM user_addresses WHERE id=%s", (addr_id,))
            conn.commit()
    return {"msg": "ok"}

@router.get("/address/list", summary="地址列表")
def address_list(mobile: str, page: int = 1, size: int = 5):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u:
                _err("用户不存在")
            rows = AddressService.get_address_list(u["id"], page, size)
            return {"rows": rows}

@router.post("/address/return", summary="商家新增退货地址（可多条，最新一条为默认）")
def return_addr_set(body: AddressReq):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 校验商家身份（兼容老表可能缺少 is_merchant 字段）
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="商家不存在或未被授予商户身份")

            # 检查是否存在 is_merchant 字段并判断是否为商家
            cur.execute("SHOW COLUMNS FROM users LIKE 'is_merchant'")
            col = cur.fetchone()
            if not col:
                # 表中没有 is_merchant 字段，视为未被授予商户身份
                raise HTTPException(status_code=404, detail="商家不存在或未被授予商户身份")

            # 使用动态表访问读取用户的 is_merchant 字段以确认身份
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "is_merchant"]
            )
            cur.execute(select_sql, (body.mobile,))
            u2 = cur.fetchone()
            if not u2 or u2.get("is_merchant") != 1:
                raise HTTPException(status_code=404, detail="商家不存在或未被授予商户身份")

            user_id = u2["id"]

            # 2. 嗅探真实字段
            cur.execute("SHOW COLUMNS FROM user_addresses")
            cols = [r["Field"] for r in cur.fetchall()]

            # 3. 准备写入字典
            data = {
                "user_id": user_id,
                "consignee_name": body.name,
                "consignee_phone": body.phone,
                "province": body.province,
                "city": body.city,
                "district": body.district,
                "detail": body.detail,
                "label": body.label,
                "is_default": True,   # 新地址设为默认
                "addr_type": "return",
            }
            if body.lng is not None:
                data["lng"] = body.lng
            if body.lat is not None:
                data["lat"] = body.lat

            # 4. 过滤掉表不存在的字段
            insert_data = {k: v for k, v in data.items() if k in cols}
            if not insert_data:
                raise RuntimeError("user_addresses 表无可用字段，请检查表结构")

            # 5. 把该商家其他退货地址取消默认
            if "addr_type" in cols:
                cur.execute(
                    "UPDATE user_addresses SET is_default=0 WHERE user_id=%s AND addr_type='return'",
                    (user_id,)
                )
            else:
                cur.execute(
                    "UPDATE user_addresses SET is_default=0 WHERE user_id=%s",
                    (user_id,)
                )

            # 6. 插入新退货地址
            sql_cols = ",".join(insert_data.keys())
            placeholders = ",".join(["%s"] * len(insert_data))
            sql = f"INSERT INTO user_addresses({sql_cols}) VALUES ({placeholders})"
            cur.execute(sql, tuple(insert_data.values()))
            addr_id = cur.lastrowid
            conn.commit()
            return {"addr_id": addr_id}

@router.get("/address/return", summary="查看退货地址")
def return_addr_get(mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u:
                _err("商家不存在")
            addr = AddressService.get_default_address(u["id"])
            if not addr:
                _err("未设置退货地址")
            return addr

# 积分模块
@router.post("/points", summary="增减积分")
def points(body: PointsReq):
    try:
        from decimal import Decimal
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur,
                    "users",
                    where_clause="mobile=%s",
                    select_fields=["id"]
                )
                cur.execute(select_sql, (body.mobile,))
                row = cur.fetchone()
                if not row:
                    raise HTTPException(status_code=404, detail="用户不存在")
                user_id = row["id"]
        add_points(user_id, body.type, Decimal(str(body.amount)), body.reason)
        return {"msg": "ok"}
    except ValueError as e:
        _err(str(e))

@router.get("/points/balance", summary="积分余额")
def points_balance(mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 使用动态表访问，自动处理字段不存在的情况
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["member_points", "merchant_points", "withdrawable_balance"]
            )
            cur.execute(select_sql, (mobile,))
            row = cur.fetchone()
            if not row:
                _err("用户不存在")
            return row

@router.get("/points/log", summary="积分流水")
def points_log(mobile: str, points_type: str = "member", page: int = 1, size: int = 10):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u:
                _err("用户不存在")
            
            # 动态获取 points_log 表结构并构造 SELECT
            structure = get_table_structure(cur, "points_log")
            select_fields = []
            for field in structure['fields']:
                if field in structure['asset_fields']:
                    select_fields.append(f"COALESCE({field}, 0) AS {field}")
                else:
                    select_fields.append(field)
            
            # 处理可能不存在的资产字段（如果表结构中没有这些字段，添加默认值）
            required_asset_fields = ['change_amount', 'balance_after']
            for asset_field in required_asset_fields:
                if asset_field not in structure['fields']:
                    select_fields.append(f"0 AS {asset_field}")
            
            where, args = ["user_id=%s", "type=%s"], [u["id"], points_type]  # 修改为正确的列名 type
            sql_where = " AND ".join(where)
            sql = f"""
                SELECT {', '.join(select_fields)}
                FROM points_log
                WHERE {sql_where}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """
            args.extend([size, (page - 1) * size])
            cur.execute(sql, tuple(args))
            rows = cur.fetchall()
            cur.execute(f"SELECT COUNT(*) AS c FROM points_log WHERE {sql_where}", tuple(args[:-2]))
            total = cur.fetchone()["c"]
            return {"rows": rows, "total": total, "page": page, "size": size}

# 团队奖励模块
@router.get("/reward/list", summary="我的团队奖励")
def reward_list(mobile: str, page: int = 1, size: int = 10):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id"]
            )
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u:
                _err("用户不存在")
            rows = TeamRewardService.get_reward_list_by_user(u["id"], page, size)
            return {"rows": rows}

@router.get("/reward/by-order/{order_id}", summary="按订单查看奖励")
def reward_by_order(order_id: int):
    rows = TeamRewardService.get_reward_by_order(order_id)
    return {"rows": rows}

# 董事模块
@router.post("/director/try-promote", summary="晋升荣誉董事")
def director_try_promote(user_id: int):
    ok = DirectorService.try_promote(user_id)
    return {"success": ok}

@router.get("/director/is", summary="是否荣誉董事")
def director_is(user_id: int):
    return {"is_director": DirectorService.is_director(user_id)}

@router.get("/director/dividend", summary="分红明细")
def director_dividend(user_id: int, page: int = 1, size: int = 10):
    rows = DirectorService.get_dividend_detail(user_id, page, size)
    return {"rows": rows}

@router.get("/director/list", summary="所有活跃董事")
def director_list(page: int = 1, size: int = 10):
    rows = DirectorService.list_all_directors(page, size)
    return {"rows": rows}

@router.post("/director/calc-week", summary="手动触发周分红（仅内部）")
def director_calc_week(period: datetime.date):
    total_paid = DirectorService.calc_week_dividend(period)
    return {"total_paid": total_paid}

# 审计日志
@router.get("/audit", summary="等级变动审计")
def audit_list(mobile: str = None, page: int = 1, size: int = 10):
    where, args = "", []
    if mobile:
        where = "WHERE u.mobile=%s"
        args.append(mobile)
    with get_conn() as conn:
        with conn.cursor() as cur:
            count_sql = f"SELECT COUNT(*) AS c FROM audit_log a JOIN users u ON u.id=a.user_id {where}"
            cur.execute(count_sql, tuple(args))
            total = cur.fetchone()["c"]
            sql = f"""
                SELECT u.mobile, a.old_val, a.new_val, a.reason, a.created_at
                FROM audit_log a
                JOIN users u ON u.id=a.user_id
                {where}
                ORDER BY a.created_at DESC
                LIMIT %s OFFSET %s
            """
            args.extend([size, (page - 1) * size])
            cur.execute(sql, tuple(args))
            rows = cur.fetchall()
            return {"rows": rows, "total": total, "page": page, "size": size}

@router.post("/user/grant-merchant", summary="后台赋予商户身份（动态字段/自动升级表）")
def grant_merchant(mobile: str, admin_key: str):
    if admin_key != "gm2025":
        raise HTTPException(status_code=403, detail="口令错误")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 嗅探 users 表真实字段
            cur.execute("SHOW COLUMNS FROM users")
            cols = [r["Field"] for r in cur.fetchall()]

            # 2. 若不存在 is_merchant，则自动加字段
            if "is_merchant" not in cols:
                cur.execute(
                    "ALTER TABLE users ADD COLUMN is_merchant TINYINT(1) NOT NULL DEFAULT 0 COMMENT '0-普通用户 1-商户'"
                )
                conn.commit()          # 提交 DDL

            # 3. 执行更新
            cur.execute(
                "UPDATE users SET is_merchant=1 WHERE mobile=%s AND is_merchant=0",
                (mobile,)
            )
            if cur.rowcount == 0:
                # 要么手机号不存在，要么已经是商户
                select_sql = build_dynamic_select(
                    cur,
                    "users",
                    where_clause="mobile=%s",
                    select_fields=["1"]
                )
                cur.execute(select_sql, (mobile,))
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail="用户不存在")
                return {"msg": "已拥有商户身份，无需重复赋予"}

            conn.commit()
            return {"msg": "已赋予商户身份"}

@router.get("/user/is-merchant", summary="查询是否商户")
def is_merchant(mobile: str):
    return {"is_merchant": UserService.is_merchant(mobile)}


@router.post("/user/wechat-login", summary="微信小程序登录")
async def wechat_login(request: Request):
    """微信小程序登录接口"""
    # 确保 users 表存在 openid 字段（兼容旧库）
    WechatService.ensure_openid_column()

    data = await request.json()
    code = data.get('code')
    nick_name = data.get('nickName')

    if not code or not nick_name:
        raise HTTPException(status_code=400, detail="缺少参数")

    try:
        # 调用微信接口，通过code换取openid和session_key
        openid, session_key = WechatService.get_openid_by_code(code)

        # 检查用户是否已注册
        user = WechatService.check_user_by_openid(openid)
        if not user:
            # 注册新用户
            user_id = WechatService.register_user(openid, nick_name)
        else:
            user_id = user['id']

        # 生成token并返回
        token = WechatService.generate_token(user_id)
        return {
            "success": True,
            "user_id": user_id,
            "token": token
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.exception("微信登录失败")
        # 为避免将原始异常（可能包含 Decimal 等不可序列化对象）放入响应，返回简单错误信息
        raise HTTPException(status_code=500, detail="微信登录失败")
