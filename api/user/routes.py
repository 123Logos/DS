from fastapi import HTTPException, APIRouter, Request,File, UploadFile,Path, Depends
import uuid
import datetime

from models.schemas.user import (
    SetStatusReq, AuthReq, AuthResp, UpdateProfileReq, SelfDeleteReq,
    FreezeReq, ResetPwdReq, AdminResetPwdReq, SetLevelReq, AddressReq,
    UpdateAddressReq,
    PointsReq, UserInfoResp, BindReferrerReq,MobileResp,Query,AvatarUploadResp,
    UnilevelStatusResponse, UnilevelPromoteResponse,UserAllPointsResponse,UserPointsSummaryResponse,SetUnilevelReq,
    ReferralQRResponse,DecryptPhoneReq, DecryptPhoneResp
)

from core.database import get_conn
from core.logging import get_logger
from core.table_access import build_dynamic_select, get_table_structure, _quote_identifier
from core.auth import create_access_token  # ✅ 新增：导入 Token 创建函数
from services.user_service import UserService, UserStatus, verify_pwd, hash_pwd
from services.address_service import AddressService
from services.points_service import add_points
from services.reward_service import TeamRewardService
from services.director_service import DirectorService
from services.wechat_service import WechatService
from core.table_access import build_select_list
from typing import List

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
    """
    用户认证接口
    - 支持自动注册
    - 返回持久化的 JWT/UUID Token
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="mobile=%s",
                select_fields=["id", "password_hash", "member_level", "status", "name"]
            )
            cur.execute(select_sql, (body.mobile,))
            row = cur.fetchone()

            is_new_user = False

            if row:
                # 已有用户：验证密码
                if not verify_pwd(body.password, row["password_hash"]):
                    raise HTTPException(status_code=400, detail="手机号或密码错误")

                status = row["status"]
                if status == UserStatus.FROZEN:
                    raise HTTPException(status_code=403, detail="账号已冻结")
                if status == UserStatus.DELETED:
                    raise HTTPException(status_code=403, detail="账号已注销")

                user_id = row["id"]
                level = row["member_level"]
                name = row["name"]
            else:
                # 新用户：自动注册
                try:
                    user_id = UserService.register(
                        mobile=body.mobile,
                        pwd=body.password,
                        name=body.name,
                        referrer_mobile=None
                    )
                    level = 0
                    is_new_user = True
                    name = body.name
                except ValueError as e:
                    raise HTTPException(status_code=400, detail=str(e))

            # ✅ 关键修复：创建并持久化 Token（保存到 sessions 表或 users.token 字段）
            token = create_access_token(user_id, token_type="uuid")

            logger.info(f"用户认证成功 - ID: {user_id}, 手机: {body.mobile}, Token: {token[:8]}...")

            return AuthResp(
                uid=user_id,
                token=token,
                level=level,
                is_new=is_new_user
            )

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
            set_clause = ", ".join([f"{_quote_identifier(k)}=%s" for k in updates])
            sql = f"UPDATE {_quote_identifier('users')} SET {set_clause} WHERE id=%s"
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
            set_parts.append(f"{_quote_identifier('member_level')}=%s")
            args.append(new_level)
            if "level_changed_at" in cols:
                set_parts.append(f"{_quote_identifier('level_changed_at')}=NOW()")
            sql = f"UPDATE users SET {build_select_list(set_parts)} WHERE id=%s"
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

            set_clause = ", ".join([f"{_quote_identifier(k)}=NOW()" if v == "NOW()" else f"{_quote_identifier(k)}=%s" for k, v in updates.items()])
            sql = f"UPDATE {_quote_identifier('users')} SET {set_clause} WHERE id=%s"
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
                "SELECT id, mobile, name, avatar_path, member_level, is_merchant, status, referral_code "
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
            is_merchant=u.get("is_merchant", 0) or 0,
        status=u["status"],
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


@router.get("/user/list", summary="分页用户列表+筛选")
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

    # ❌ 删除或注释掉以下两行
    # limit_sql = "LIMIT %s OFFSET %s"
    # args.extend([size, (page - 1) * size])

    # ✅ 新增：直接生成 MySQL 风格的 limit 字符串
    offset = (page - 1) * size
    limit_str = f"{offset}, {size}"

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 使用动态表访问构造查询
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause=sql_where.replace("WHERE ", "") if sql_where else None,
                order_by="id",
                limit=limit_str,  # ✅ 直接传入确定的字符串
                select_fields=["id", "mobile", "name", "member_level", "created_at"]
            )
            cur.execute(select_sql, tuple(args))
            rows = cur.fetchall()

            # COUNT 查询
            count_sql = f"SELECT COUNT(*) AS c FROM users {sql_where}"
            cur.execute(count_sql, tuple(args))  # ✅ 移除 [:-2]
            total = cur.fetchone()["c"]

            return {"rows": rows, "total": total, "page": page, "size": size}


@router.post("/user/bind-referrer", summary="绑定推荐人（防重复/防循环/支持推荐码或手机号）")
def bind_referrer(body: BindReferrerReq):
    """
    优先级：referrer_code > referrer_mobile > 跳过
    限制：已有推荐人时禁止重复绑定，防止循环推荐关系
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            # ========== 1. 被推荐人验证 ==========
            select_sql = build_dynamic_select(cur, "users",
                                              where_clause="mobile=%s", select_fields=["id", "status"])
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u or u["status"] == UserStatus.DELETED.value:
                raise HTTPException(status_code=404, detail="被推荐人不存在或已注销")
            user_id = u["id"]

            # ========== 2. 防重复绑定（核心防护） ==========
            cur.execute("SELECT referrer_id FROM user_referrals WHERE user_id=%s", (user_id,))
            existing_referrer = cur.fetchone()
            if existing_referrer:
                raise HTTPException(
                    status_code=400,
                    detail="已有推荐人，不能重复绑定"
                )

            # ========== 3. 确定推荐人ID ==========
            referrer_id = None
            if body.referrer_code:  # 优先用推荐码
                select_sql = build_dynamic_select(cur, "users",
                                                  where_clause="referral_code=%s", select_fields=["id", "status"])
                cur.execute(select_sql, (body.referrer_code.upper(),))
                ref = cur.fetchone()
                if not ref or ref["status"] == UserStatus.DELETED.value:
                    raise HTTPException(status_code=404, detail="推荐人不存在或已注销")
                referrer_id = ref["id"]
            elif body.referrer_mobile:  # 其次用手机号
                select_sql = build_dynamic_select(cur, "users",
                                                  where_clause="mobile=%s", select_fields=["id", "status"])
                cur.execute(select_sql, (body.referrer_mobile,))
                ref = cur.fetchone()
                if not ref or ref["status"] == UserStatus.DELETED.value:
                    raise HTTPException(status_code=404, detail="推荐人不存在或已注销")
                referrer_id = ref["id"]
            else:
                return {"msg": "ok"}  # 无推荐人直接返回

            # ========== 4. 防循环推荐（核心防护） ==========
            if UserService._is_ancestor(referrer_id, user_id):
                raise HTTPException(
                    status_code=400,
                    detail="不能绑定自己的下级，防止形成循环推荐关系"
                )

            # ========== 5. 写入推荐关系 ==========
            # 自动建表（兼容老库）
            cur.execute("""
                CREATE TABLE IF NOT EXISTS user_referrals (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    referrer_id INT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE KEY uk_uid (user_id),
                    KEY idx_referrer (referrer_id)
                )
            """)

            # 写入数据
            cur.execute(
                "INSERT INTO user_referrals(user_id, referrer_id) VALUES (%s,%s)",
                (user_id, referrer_id)
            )

            # 同步更新 users.referral_id 字段（若不存在则自动创建）
            cur.execute("SHOW COLUMNS FROM users LIKE 'referral_id'")
            if not cur.fetchone():
                cur.execute(
                    "ALTER TABLE users ADD COLUMN referral_id INT DEFAULT NULL COMMENT '推荐人ID'"
                )

            cur.execute("UPDATE users SET referral_id=%s WHERE id=%s", (referrer_id, user_id))
            conn.commit()

            logger.info(f"推荐绑定成功: 用户ID={user_id}, 推荐人ID={referrer_id}")
            return {"msg": "绑定成功"}

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
            # 1. 取用户id
            select_sql = build_dynamic_select(cur, "users", where_clause="mobile=%s", select_fields=["id"])
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            user_id = u["id"]

            # 2. 嗅探真实字段
            cur.execute("SHOW COLUMNS FROM addresses")
            cols = [r["Field"] for r in cur.fetchall()]

            # 3. 只保留表里存在的字段
            data = {
                "user_id": user_id,
                "name": body.name,           # 表里字段
                "phone": body.phone,         # 表里字段
                "province": body.province,
                "city": body.city,
                "district": body.district,
                "detail": body.detail,
                "is_default": body.is_default,
                "addr_type": body.addr_type,
            }
            insert_data = {k: v for k, v in data.items() if k in cols}
            if not insert_data:
                raise RuntimeError("addresses表无可用字段")

            # 4. 插入
            sql_cols = ",".join([_quote_identifier(k) for k in insert_data.keys()])
            placeholders = ",".join(["%s"] * len(insert_data))
            sql = f"INSERT INTO {_quote_identifier('addresses')}({sql_cols}) VALUES ({placeholders})"
            cur.execute(sql, tuple(insert_data.values()))
            addr_id = cur.lastrowid

            # 5. 取消其它默认
            if body.is_default:
                cur.execute(
                    "UPDATE addresses SET is_default=0 WHERE user_id=%s AND id!=%s",
                    (user_id, addr_id)
                )
            conn.commit()
            return {"addr_id": addr_id}


@router.put("/address/{addr_id}", summary="更新地址（部分字段可选）")
def address_update(addr_id: int, body: UpdateAddressReq):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 验证用户存在并获取 user_id
            select_sql = build_dynamic_select(cur, "users", where_clause="mobile=%s", select_fields=["id"])
            cur.execute(select_sql, (body.mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            user_id = u["id"]

            # 2. 准备更新字段（只包含非 None 的字段，且不包含 mobile）
            data = body.model_dump(exclude_none=True)
            data.pop("mobile", None)
            if not data:
                raise HTTPException(status_code=400, detail="无更新内容")

            # 3. 调用服务方法执行更新（AddressService 会做列名校验）
            try:
                AddressService.update_address(user_id, addr_id, **data)
                conn.commit()
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e))

    return {"msg": "ok"}
@router.put("/address/default", summary="设为默认地址")
def set_default_addr(addr_id: int, mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 校验地址存在且属于当前用户
            cur.execute("SELECT user_id FROM addresses WHERE id=%s", (addr_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="地址不存在")
            addr_user_id = row["user_id"]

            select_sql = build_dynamic_select(cur, "users", where_clause="mobile=%s", select_fields=["id"])
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u or u["id"] != addr_user_id:
                raise HTTPException(status_code=403, detail="地址不属于当前用户")

            # 取消同用户其它默认
            cur.execute("UPDATE addresses SET is_default=0 WHERE user_id=%s", (addr_user_id,))
            cur.execute("UPDATE addresses SET is_default=1 WHERE id=%s", (addr_id,))
            conn.commit()
    return {"msg": "ok"}

@router.delete("/address/{addr_id}", summary="删除地址")
def delete_addr(addr_id: int, mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM addresses WHERE id=%s", (addr_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="地址不存在")
            addr_user_id = row["user_id"]

            select_sql = build_dynamic_select(cur, "users", where_clause="mobile=%s", select_fields=["id"])
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u or u["id"] != addr_user_id:
                raise HTTPException(status_code=403, detail="地址不属于当前用户")

            cur.execute("DELETE FROM addresses WHERE id=%s", (addr_id,))
            conn.commit()
    return {"msg": "ok"}

@router.get("/address/list", summary="地址列表")
def address_list(mobile: str, page: int = 1, size: int = 5):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(cur, "users", where_clause="mobile=%s", select_fields=["id"])
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            rows = AddressService.get_address_list(u["id"], page, size)
            return {"rows": rows}

@router.post("/address/return", summary="商家新增退货地址")
def return_addr_set(body: AddressReq):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 校验商家身份
            select_sql = build_dynamic_select(cur, "users", where_clause="mobile=%s", select_fields=["id", "is_merchant"])
            cur.execute(select_sql, (body.mobile,))
            u2 = cur.fetchone()
            if not u2 or u2.get("is_merchant") != 1:
                raise HTTPException(status_code=404, detail="商家不存在或未被授予商户身份")
            user_id = u2["id"]

            # 2. 嗅探字段
            cur.execute("SHOW COLUMNS FROM addresses")
            cols = [r["Field"] for r in cur.fetchall()]

            # 3. 写入数据（仅保留表存在的字段）
            data = {
                "user_id": user_id,
                "name": body.name,
                "phone": body.phone,
                "province": body.province,
                "city": body.city,
                "district": body.district,
                "detail": body.detail,
                "is_default": True,
                "addr_type": "return",
            }
            insert_data = {k: v for k, v in data.items() if k in cols}

            # 4. 取消其它退货默认
            cur.execute("UPDATE addresses SET is_default=0 WHERE user_id=%s AND addr_type='return'", (user_id,))
            # 5. 插入
            sql_cols = ",".join([_quote_identifier(k) for k in insert_data.keys()])
            placeholders = ",".join(["%s"] * len(insert_data))
            sql = f"INSERT INTO {_quote_identifier('addresses')}({sql_cols}) VALUES ({placeholders})"
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


# ========== 新增：平台退货地址接口 ==========

@router.get("/address/platform-return", summary="查询平台退货地址（公开）")
def get_platform_return_address():
    """
    所有用户都能查看的平台退货地址
    无需登录认证
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 查询 user_id=0 的平台退货地址
            cur.execute("""
                SELECT id, name, phone, province, city, district, detail, 
                       is_default, addr_type, created_at, updated_at
                FROM addresses 
                WHERE user_id = 0 AND addr_type = 'return'
                ORDER BY is_default DESC, id DESC
                LIMIT 1
            """)
            addr = cur.fetchone()

            if not addr:
                raise HTTPException(status_code=404, detail="平台退货地址尚未设置")

            return {
                "id": addr["id"],
                "name": addr["name"],
                "phone": addr["phone"],
                "province": addr["province"],
                "city": addr["city"],
                "district": addr["district"],
                "detail": addr["detail"],
                "is_default": bool(addr["is_default"])
            }


@router.post("/admin/platform-return-address", summary="设置平台退货地址（管理员）")
def set_platform_return_address(
        name: str = Query(..., description="收货人姓名"),
        phone: str = Query(..., description="联系电话"),
        province: str = Query(..., description="省份"),
        city: str = Query(..., description="城市"),
        district: str = Query(..., description="区县"),
        detail: str = Query(..., description="详细地址"),
        admin_key: str = Query(..., description="后台口令")
):
    if admin_key != "admin2025":
        raise HTTPException(status_code=403, detail="后台口令错误")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # ==================== 新增：临时禁用外键检查 ====================
            cur.execute("SET FOREIGN_KEY_CHECKS = 0")
            # ============================================================

            # 查询是否已存在平台地址
            cur.execute("""
                SELECT id FROM addresses 
                WHERE user_id = 0 AND addr_type = 'return'
            """)
            existing = cur.fetchone()

            # 准备数据（user_id固定为0）
            data = {
                "user_id": 0,
                "name": name,
                "phone": phone,
                "province": province,
                "city": city,
                "district": district,
                "detail": detail,
                "is_default": True,
                "addr_type": "return"
            }

            if existing:
                # 更新现有地址
                addr_id = existing["id"]
                sql = """
                    UPDATE addresses 
                    SET name=%s, phone=%s, province=%s, city=%s, 
                        district=%s, detail=%s, updated_at=NOW()
                    WHERE id=%s
                """
                cur.execute(sql, (
                    data["name"], data["phone"], data["province"],
                    data["city"], data["district"], data["detail"], addr_id
                ))
            else:
                # 插入新地址
                sql = """
                    INSERT INTO addresses 
                    (user_id, name, phone, province, city, district, 
                     detail, is_default, addr_type)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cur.execute(sql, (
                    data["user_id"], data["name"], data["phone"],
                    data["province"], data["city"], data["district"],
                    data["detail"], data["is_default"], data["addr_type"]
                ))

            # ==================== 新增：重新启用外键检查 ====================
            cur.execute("SET FOREIGN_KEY_CHECKS = 1")
            conn.commit()
            # ============================================================

            return {"msg": "平台退货地址已设置/更新"}



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
                    select_fields.append(f"COALESCE({_quote_identifier(field)}, 0) AS {_quote_identifier(field)}")
                else:
                    select_fields.append(_quote_identifier(field))
            
            # 处理可能不存在的资产字段（如果表结构中没有这些字段，添加默认值）
            required_asset_fields = ['change_amount', 'balance_after']
            for asset_field in required_asset_fields:
                if asset_field not in structure['fields']:
                    select_fields.append(f"0 AS {_quote_identifier(asset_field)}")
            
            where, args = ["user_id=%s", "type=%s"], [u["id"], points_type]  # 修改为正确的列名 type
            sql_where = " AND ".join(where)

            sql = f"""
                SELECT {build_select_list(select_fields)}
                FROM {_quote_identifier('points_log')}
                WHERE {sql_where}
                ORDER BY created_at DESC
                LIMIT %s OFFSET %s
            """
            args.extend([size, (page - 1) * size])
            cur.execute(sql, tuple(args))
            rows = cur.fetchall()
            cur.execute(f"SELECT COUNT(*) AS c FROM {_quote_identifier('points_log')} WHERE {sql_where}", tuple(args[:-2]))
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
# @router.post("/director/try-promote", summary="晋升荣誉董事")
# def director_try_promote(user_id: int):
#     ok = DirectorService.try_promote(user_id)
#     return {"success": ok}
#
# @router.get("/director/is", summary="是否荣誉董事")
# def director_is(user_id: int):
#     return {"is_director": DirectorService.is_director(user_id)}
#
# @router.get("/director/dividend", summary="分红明细")
# def director_dividend(user_id: int, page: int = 1, size: int = 10):
#     rows = DirectorService.get_dividend_detail(user_id, page, size)
#     return {"rows": rows}
#
# @router.get("/director/list", summary="所有活跃董事")
# def director_list(page: int = 1, size: int = 10):
#     rows = DirectorService.list_all_directors(page, size)
#     return {"rows": rows}
#
# @router.post("/director/calc-week", summary="手动触发周分红（仅内部）")
# def director_calc_week(period: datetime.date):
#     total_paid = DirectorService.calc_week_dividend(period)
#     return {"total_paid": total_paid}
#
# # 审计日志
# @router.get("/audit", summary="等级变动审计")
# def audit_list(mobile: str = None, page: int = 1, size: int = 10):
#     where, args = "", []
#     if mobile:
#         where = "WHERE u.mobile=%s"
#         args.append(mobile)
#     with get_conn() as conn:
#         with conn.cursor() as cur:
#             count_sql = f"SELECT COUNT(*) AS c FROM audit_log a JOIN users u ON u.id=a.user_id {where}"
#             cur.execute(count_sql, tuple(args))
#             total = cur.fetchone()["c"]
#             sql = f"""
#                 SELECT u.mobile, a.old_val, a.new_val, a.reason, a.created_at
#                 FROM audit_log a
#                 JOIN users u ON u.id=a.user_id
#                 {where}
#                 ORDER BY a.created_at DESC
#                 LIMIT %s OFFSET %s
#             """
#             args.extend([size, (page - 1) * size])
#             cur.execute(sql, tuple(args))
#             rows = cur.fetchall()
#             return {"rows": rows, "total": total, "page": page, "size": size}

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


@router.post("/wechat/login", summary="微信小程序登录")
async def wechat_login(request: Request):
    """微信小程序登录接口 - 使用124位专用Token"""
    # 确保 users 表存在 openid 字段（兼容旧库）
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SET FOREIGN_KEY_CHECKS = 0")  #-- ✅ 临时禁用外键
                WechatService.ensure_openid_column()
                cur.execute("SET FOREIGN_KEY_CHECKS = 1")  #-- ✅ 恢复外键检查
                conn.commit()
    except Exception as e:
        logger.warning(f"确保openid字段时出错: {e}")  #-- 非致命错误，继续执行

    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON payload")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="invalid JSON payload")

    code = data.get('code')
    nick_name = data.get('nickName')

    if not code or not nick_name:
        raise HTTPException(status_code=400, detail="缺少参数")

    try:
        # 调用微信接口，通过 code 换取 openid、session_key（可选 unionid）
        result = WechatService.get_openid_by_code(code)
        # 支持返回 (openid, session_key) 或 (openid, session_key, unionid)
        if isinstance(result, (list, tuple)):
            if len(result) >= 2:
                openid, session_key = result[0], result[1]
            else:
                openid, session_key = result, ""
            unionid = result[2] if len(result) >= 3 else ""
        else:
            openid = result
            session_key = ""
            unionid = ""

        # 检查用户是否已注册
        user = WechatService.check_user_by_openid(openid)
        is_new_user = False

        if not user:
            # 注册新用户
            user_id = WechatService.register_user(openid, nick_name)
            level = 0
            is_new_user = True
        else:
            user_id = user['id']
            level = user.get('member_level', 0)
            is_new_user = False

        # ✅ 关键修改：使用微信专用Token类型，生成124位Token
        token = create_access_token(user_id, token_type="wechat")

        logger.info(f"微信登录成功 - 用户ID: {user_id}, Token: {token[:20]}..., Token长度: {len(token)}, openid={openid}")

        # 返回给前端额外的微信凭证，方便前端保存 openid/session_key/unionid
        return {
            "uid": user_id,
            "token": token,
            "level": level,
            "is_new": is_new_user,
            "openid": openid,
            "session_key": session_key,
            "unionid": unionid or ""
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("微信登录失败")
        raise HTTPException(status_code=500, detail="微信登录失败")

@router.get("/user/mobile", response_model=MobileResp, summary="根据用户ID获取手机号")
def get_mobile_by_uid(
    user_id: int = Query(..., gt=0, description="用户ID"),
    key: str = Query(..., description="后台口令")
):
    if key != "gm2025":
        raise HTTPException(status_code=403, detail="口令错误")

    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur, "users", where_clause="id=%s", select_fields=["mobile"]
            )
            cur.execute(select_sql, (user_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="用户不存在")
            return {"mobile": row["mobile"]}

@router.put("/user/mobile", summary="后台修改手机号（无验证码）")
def change_mobile(
    user_id: int = Query(..., gt=0, description="用户ID"),
    old_mobile: str = Query(..., description="原手机号"),
    new_mobile: str = Query(..., description="新手机号"),
    key: str = Query(..., description="后台口令")
):
    if key != "gm2025":
        raise HTTPException(status_code=403, detail="口令错误")

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 旧手机号是否属于该用户
            select_sql = build_dynamic_select(
                cur, "users", where_clause="id=%s AND mobile=%s", select_fields=["id"]
            )
            cur.execute(select_sql, (user_id, old_mobile))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="旧手机号与用户不匹配")

            # 2. 新号是否已被占用
            select_sql = build_dynamic_select(
                cur, "users", where_clause="mobile=%s", select_fields=["1"]
            )
            cur.execute(select_sql, (new_mobile,))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="新手机号已被注册")

            # 3. 更新
            cur.execute("UPDATE users SET mobile=%s WHERE id=%s", (new_mobile, user_id))
            conn.commit()
            return {"msg": "手机号已更新"}



# 后台晋升

# 前端查询
@router.get("/user/unilevel", summary="当前联创等级")
def get_unilevel(mobile: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(cur, "users", where_clause="mobile=%s", select_fields=["id"])
            cur.execute(select_sql, (mobile,))
            u = cur.fetchone()
            if not u:
                raise HTTPException(status_code=404, detail="用户不存在")
            level = UserService.get_unilevel(u["id"])
            return {"unilevel": level}

@router.post("/user/{user_id}/avatar", summary="上传用户头像", response_model=AvatarUploadResp)
def upload_avatar(
    user_id: int = Path(..., gt=0, description="用户ID"),
    avatar_files: List[UploadFile] = File(
        [],
        description="头像文件，1-3张，单张≤2MB，仅JPG/PNG/WEBP，留空则清空头像"
    )
):
    """
    行为与 /api/products/{id}/images 完全一致：
    1. Path 参数
    2. 支持多张（数组）
    3. 返回数组 URL
    4. 留空则清空原有头像
    """
    try:
        urls = UserService.upload_avatar(user_id, avatar_files)
        return AvatarUploadResp(avatar_urls=urls, uploaded_at=datetime.datetime.now())
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"头像上传失败：{e}")

@router.get("/my", summary="查询我的优惠券")
def get_my_coupons(
    status: str = "all",
    page: int = 1,
    page_size: int = 20,
    user_id: int = Query(..., description="用户ID")  # ← 改为必填查询参数
):
    """查询指定用户的优惠券（user_id从查询参数获取）"""
    service = UserService()
    return service.query_user_coupons(
        user_id=user_id,
        status=status,
        page=page,
        page_size=page_size
    )

@router.get("/unilevel/status", response_model=UnilevelStatusResponse, summary="查询联创状态")
def get_unilevel_status(
    user_id: int = Query(..., description="用户ID")
):
    """
    查询用户的联创等级和晋升状态
    - 返回当前等级、应得等级、是否可晋升
    """
    try:
        service = UserService()
        status = service.get_unilevel_status(user_id)
        return status
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/unilevel/promote", response_model=UnilevelPromoteResponse, summary="自动晋升联创")
def promote_unilevel(
    user_id: int = Query(..., description="用户ID")
):
    """
    后端自动计算并晋升联创等级
    - 无需传入level，自动晋升到应得等级
    - 如果已是最高等级返回错误
    """
    try:
        service = UserService()
        new_level = service.promote_unilevel_auto(user_id)
        return {
            "new_level": new_level,
            "message": f"晋升成功！当前为联创{new_level}星"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

'''
@router.get("/special-points", response_model=UserSpecialPointsResponse, summary="查询推荐和团队奖励点数")
def get_user_special_points(
    user_id: int = Query(..., description="用户ID", gt=0)
):
    """
    查询用户的团队奖励和推荐奖励专用点数
    """
    try:
        service = UserService()
        points_data = service.get_user_special_points(user_id)
        return points_data
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")

@router.get("/subsidy-points", response_model=UserSubsidyPointsResponse, summary="查询周补贴专用点数")
def get_user_subsidy_points(
    user_id: int = Query(..., description="用户ID", gt=0)
):
    """
    查询用户的周补贴专用点数余额
    """
    try:
        service = UserService()
        points_data = service.get_user_subsidy_points(user_id)
        return points_data
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")

@router.get("/unilevel-points", response_model=UserUnilevelPointsResponse, summary="查询联创星级专用点数")
def get_user_unilevel_points(
    user_id: int = Query(..., description="用户ID", gt=0)
):
    """
    查询用户的联创星级专用点数余额
    """
    try:
        service = UserService()
        points_data = service.get_user_unilevel_points(user_id)
        return points_data
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")
'''

@router.get("/all-points", response_model=UserAllPointsResponse, summary="查询用户四个点数总和")
def get_user_all_points(
    user_id: int = Query(..., description="用户ID", gt=0)
):
    """
    查询用户的四个专用点数（联创星级、周补贴、团队奖励、推荐奖励）及总和
    """
    try:
        points_data = UserService.get_user_all_points(user_id)
        return points_data
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")
'''

@router.post("/points/clear-reward", summary="后台一键清除推荐和团队奖励点数")
def clear_reward_points(body: ClearRewardPointsReq):
    """
    清除用户的团队奖励专用点数和推荐奖励专用点数

    权限验证：需要正确的admin_key
    操作记录：自动记录到points_clear_log审计表
    幂等性：如果点数已为0，返回无需清除提示
    """
    if body.admin_key != "admin2025":
        raise HTTPException(status_code=403, detail="后台口令错误")

    try:
        result = UserService.clear_reward_points(body.user_id, body.reason)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"清除失败: {str(e)}")


@router.post("/points/clear-subsidy", summary="后台一键清除周补贴点数")
def clear_subsidy_points(body: ClearSubsidyPointsReq):
    """
    清除用户的周补贴专用点数

    权限验证：需要正确的admin_key
    幂等性：如果点数已为0，返回无需清除提示
    """
    if body.admin_key != "admin2025":
        raise HTTPException(status_code=403, detail="后台口令错误")

    try:
        result = UserService.clear_subsidy_points(body.user_id, body.reason)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"清除失败: {str(e)}")


@router.post("/points/clear-unilevel", summary="后台一键清除联创星级点数")
def clear_unilevel_points(body: ClearUnilevelPointsReq):
    """
    清除用户的联创星级专用点数

    权限验证：需要正确的admin_key
    幂等性：如果点数已为0，返回无需清除提示
    """
    if body.admin_key != "admin2025":
        raise HTTPException(status_code=403, detail="后台口令错误")

    try:
        result = UserService.clear_unilevel_points(body.user_id, body.reason)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"清除失败: {str(e)}")
'''

@router.get("/points/summary", response_model=UserPointsSummaryResponse, summary="查询用户点数汇总（累计/已用/剩余）")
def get_points_summary(
    user_id: int = Query(..., description="用户ID", gt=0)
):
    """
    查询用户的点数完整信息：
    - 四个渠道的累计获得点数
    - 累计总值（四个渠道之和）
    - 剩余可用点数（true_total_points）
    - 已使用点数（累计 - 剩余）
    """
    try:
        summary = UserService.get_points_summary(user_id)
        return summary
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"查询失败: {str(e)}")


@router.post("/admin/unilevel/set", summary="后台设置联创星级")
def set_unilevel(body: SetUnilevelReq):
    """
    后台直接设置用户的联创星级等级

    权限验证：需要正确的admin_key
    自动建表：user_unilevel 表不存在时自动创建
    幂等性：等级未变化时返回提示
    """
    if body.admin_key != "admin2025":
        raise HTTPException(status_code=403, detail="后台口令错误")

    try:
        result = UserService.set_unilevel(body.user_id, body.level)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"操作失败: {str(e)}")

@router.get("/user/referral-qr", response_model=ReferralQRResponse, summary="推荐二维码获取")
def get_referral_qr(user_id: int):
    """
    获取用户的推荐码小程序码
    - 如果已生成直接返回URL
    - 如果未生成则调用微信接口生成
    - 需要配置 WECHAT_APP_ID 和 WECHAT_APP_SECRET
    """
    try:
        qr_url = UserService.get_referral_qr_url(user_id)
        if not qr_url:
            raise HTTPException(status_code=500, detail="生成二维码失败")

        return ReferralQRResponse(qr_url=qr_url, message="获取成功")
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"获取推荐码二维码失败: {e}")
        raise HTTPException(status_code=500, detail="服务器内部错误")


@router.post("/user/refresh-referral-qr", response_model=ReferralQRResponse, summary="刷新推荐二维码")
def refresh_referral_qr(user_id: int):
    """
    强制刷新用户的推荐码小程序码（重新生成）
    """
    try:
        qr_url = UserService.generate_referral_qr(user_id)
        if not qr_url:
            raise HTTPException(status_code=500, detail="生成二维码失败")

        return ReferralQRResponse(qr_url=qr_url, message="刷新成功")
    except Exception as e:
        logger.exception(f"刷新推荐码二维码失败: {e}")
        raise HTTPException(status_code=500, detail="服务器内部错误")


@router.post("/user/decrypt-phone", tags=["用户中心"], response_model=DecryptPhoneResp, summary="解密微信手机号")
def decrypt_phone(req: DecryptPhoneReq):
    """
    解密微信手机号（核心接口）

    前端发送：
    - code: 微信登录 code（必须用同一个）
    - encrypted_data: getPhoneNumber 返回的 encryptedData
    - iv: getPhoneNumber 返回的 iv
    """
    try:
        # 1. code 换 session_key
        openid, session_key = WechatService.get_openid_by_code(req.code)

        # 2. 解密手机号
        phone = WechatService.decrypt_phone_number(
            session_key=session_key,
            encrypted_data=req.encrypted_data,
            iv=req.iv
        )

        logger.info(f"✅ 手机号解密成功: {phone[:3]}****{phone[-4:]}")

        return DecryptPhoneResp(phone=phone)

    except Exception as e:
        logger.exception(f"手机号解密失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/user/avatar", tags=["用户中心"], summary="清空头像")
def clear_avatar(user_id: int):
    """
    一键清空头像
    前端调用：wx.request({ url: '/user/avatar', method: 'DELETE', ... })
    """
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 清空头像路径
                cur.execute(
                    """
                    UPDATE users 
                    SET avatar_path = NULL, updated_at = NOW() 
                    WHERE id = %s
                    """,
                    (user_id,)
                )
                conn.commit()

        logger.info(f"✅ 用户 {user_id} 清空头像成功")
        return {"message": "头像已清空", "success": True}

    except Exception as e:
        logger.exception(f"清空头像失败: {e}")
        raise HTTPException(status_code=500, detail="操作失败")