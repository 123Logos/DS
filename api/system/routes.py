# api/system/routes.py - 系统配置相关接口
from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Optional
from core.database import get_conn
from core.logging import get_logger
from models.schemas.system import SystemSentenceModel, SystemSentenceUpdate
from core.auth import require_platform_admin
from services.auth_security_service import audit

logger = get_logger(__name__)

router = APIRouter(tags=["系统配置"], responses={404: {"description": "未找到"}})


def register_routes(app):
    """注册系统配置路由到主应用"""
    app.include_router(router, prefix="/api", tags=["系统配置"])


@router.get("/system/sentences", summary="📝 获取系统标语")
def get_system_sentences():
    """
    获取轮播图语句和系统标语
    
    如果表中没有记录，则返回默认值（空字符串）
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 查询系统标语记录（只取第一条，如果有多条则取最新的）
            cur.execute("""
                SELECT id, banner_sentence, system_sentence, created_at, updated_at
                FROM system_sentence
                ORDER BY id DESC
                LIMIT 1
            """)
            result = cur.fetchone()
            
            if result:
                return {
                    "status": "success",
                    "data": {
                        "id": result.get("id"),
                        "banner_sentence": result.get("banner_sentence") or "",
                        "system_sentence": result.get("system_sentence") or "",
                        "created_at": result.get("created_at"),
                        "updated_at": result.get("updated_at")
                    }
                }
            else:
                return {"status":"success", "data":{"id":None,"banner_sentence":"","system_sentence":"","created_at":None,"updated_at":None}}


@router.put("/system/sentences", summary="✏️ 更新系统标语")
def update_system_sentences(payload: SystemSentenceUpdate, operator: dict = Depends(require_platform_admin)):
    updates = payload.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(400, "请至少提供一个要更新的字段")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,banner_sentence,system_sentence FROM system_sentence ORDER BY id DESC LIMIT 1 FOR UPDATE")
            before = cur.fetchone()
            if before:
                record_id = before["id"]
                fields = ", ".join(f"`{field}`=%s" for field in updates)
                cur.execute(f"UPDATE system_sentence SET {fields},updated_at=NOW() WHERE id=%s", tuple(updates.values())+(record_id,))
            else:
                cur.execute("INSERT INTO system_sentence(banner_sentence,system_sentence) VALUES(%s,%s)", (updates.get("banner_sentence", ""),updates.get("system_sentence", "")))
                record_id = cur.lastrowid
            cur.execute("SELECT id,banner_sentence,system_sentence,created_at,updated_at FROM system_sentence WHERE id=%s", (record_id,))
            result = cur.fetchone()
            audit(cur, operator["id"], 0, "system_sentences", before or {}, result, "后台修改系统标语")
            conn.commit()
    return {"status":"success", "message":"系统标语已更新", "data":result}


@router.post("/system/grant-system", summary="🧠给予系统权限")
def grant_system_permission(
    user_id: int = Query(..., gt=0, description="用户ID"),
    key: Optional[str] = Query(None, description="旧字段，不参与授权"),
    is_merchant: int = Query(..., ge=0, le=2, description="0普通用户/1商家/2第三方平台"),
    operator: dict = Depends(require_platform_admin),
):
    """管理员修改商户类型，权限与审计来自可信认证身份。"""
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id,is_merchant FROM users WHERE id=%s FOR UPDATE", (user_id,))
            before = cur.fetchone()
            if not before:
                raise HTTPException(404, "用户不存在")
            cur.execute("UPDATE users SET is_merchant=%s WHERE id=%s", (is_merchant,user_id))
            audit(cur, operator["id"], user_id, "system_grant_role", {"is_merchant":before["is_merchant"]}, {"is_merchant":is_merchant}, "后台修改商户类型")
            conn.commit()
    return {"msg":"is_merchant 已更新", "user_id":user_id, "is_merchant":is_merchant}

# ========== 新增省市区接口 ==========
from fastapi import HTTPException  # 如果已有导入则可省略

@router.get("/provinces", summary="获取所有省份")
def get_provinces():
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT code, name FROM regions WHERE level = 1 ORDER BY code")
            return cur.fetchall()

@router.get("/cities/{province_code}", summary="获取某省的所有城市")
def get_cities(province_code: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT code, name FROM regions WHERE parent_code = %s AND level = 2 ORDER BY code",
                (province_code,)
            )
            rows = cur.fetchall()
            if not rows:
                raise HTTPException(status_code=404, detail="未找到该省份或该省份无城市数据")
            return rows

@router.get("/districts/{city_code}", summary="获取某市的所有区县")
def get_districts(city_code: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT code, name FROM regions WHERE parent_code = %s AND level = 3 ORDER BY code",
                (city_code,)
            )
            rows = cur.fetchall()
            if not rows:
                raise HTTPException(status_code=404, detail="未找到该城市或该城市无区县数据")
            return rows

