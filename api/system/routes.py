# api/system/routes.py - 系统配置相关接口
from fastapi import APIRouter, HTTPException, Query
from typing import Optional
from core.database import get_conn
from core.logging import get_logger
from models.schemas.system import SystemSentenceModel, SystemSentenceUpdate

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
                # 如果表中没有记录，返回默认值并自动创建一条记录
                cur.execute("""
                    INSERT INTO system_sentence (banner_sentence, system_sentence)
                    VALUES ('', '')
                """)
                conn.commit()
                return {
                    "status": "success",
                    "data": {
                        "id": cur.lastrowid,
                        "banner_sentence": "",
                        "system_sentence": "",
                        "created_at": None,
                        "updated_at": None
                    }
                }


@router.put("/system/sentences", summary="✏️ 更新系统标语")
def update_system_sentences(payload: SystemSentenceUpdate):
    """
    更新轮播图语句和系统标语
    
    如果表中没有记录，则自动创建一条新记录
    如果已有记录，则更新第一条记录（按id倒序取最新的）
    """
    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 查询是否存在记录
                cur.execute("""
                    SELECT id FROM system_sentence
                    ORDER BY id DESC
                    LIMIT 1
                """)
                existing = cur.fetchone()
                
                if existing:
                    # 更新现有记录
                    update_fields = []
                    update_params = []
                    
                    if payload.banner_sentence is not None:
                        update_fields.append("banner_sentence = %s")
                        update_params.append(payload.banner_sentence)
                    
                    if payload.system_sentence is not None:
                        update_fields.append("system_sentence = %s")
                        update_params.append(payload.system_sentence)
                    
                        if update_fields:
                            from core.table_access import build_select_list
                            update_params.append(existing["id"])
                            cur.execute(f"""
                                UPDATE system_sentence
                                SET {build_select_list(update_fields)}, updated_at = NOW()
                                WHERE id = %s
                            """, tuple(update_params))
                        conn.commit()
                        
                        # 查询更新后的记录
                        cur.execute("""
                            SELECT id, banner_sentence, system_sentence, created_at, updated_at
                            FROM system_sentence
                            WHERE id = %s
                        """, (existing["id"],))
                        result = cur.fetchone()
                        
                        return {
                            "status": "success",
                            "message": "系统标语已更新",
                            "data": {
                                "id": result.get("id"),
                                "banner_sentence": result.get("banner_sentence") or "",
                                "system_sentence": result.get("system_sentence") or "",
                                "created_at": result.get("created_at"),
                                "updated_at": result.get("updated_at")
                            }
                        }
                    else:
                        # 没有提供任何更新字段
                        raise HTTPException(status_code=400, detail="请至少提供一个要更新的字段")
                else:
                    # 创建新记录
                    cur.execute("""
                        INSERT INTO system_sentence (banner_sentence, system_sentence)
                        VALUES (%s, %s)
                    """, (
                        payload.banner_sentence or "",
                        payload.system_sentence or ""
                    ))
                    conn.commit()
                    
                    # 查询新创建的记录
                    cur.execute("""
                        SELECT id, banner_sentence, system_sentence, created_at, updated_at
                        FROM system_sentence
                        WHERE id = %s
                    """, (cur.lastrowid,))
                    result = cur.fetchone()
                    
                    return {
                        "status": "success",
                        "message": "系统标语已创建",
                        "data": {
                            "id": result.get("id"),
                            "banner_sentence": result.get("banner_sentence") or "",
                            "system_sentence": result.get("system_sentence") or "",
                            "created_at": result.get("created_at"),
                            "updated_at": result.get("updated_at")
                        }
                    }
            except HTTPException:
                raise
            except Exception as e:
                conn.rollback()
                logger.error(f"更新系统标语失败: {str(e)}")
                raise HTTPException(status_code=500, detail=f"更新系统标语失败: {str(e)}")


@router.post("/system/grant-system", summary="🧠给予系统权限")
def grant_system_permission(
    user_id: int = Query(..., description="用户ID"),
    key: str = Query(..., description="后台密钥"),
    is_merchant: int = Query(..., description="商户类型：0=普通用户,1=商家,2=第三方/平台")
):
    """后台接口：通过密钥将指定用户的 `is_merchant` 设置为 0/1/2（仅允许这三种值）"""
    # 密钥校验
    if key != "fheq083@$!":
        raise HTTPException(status_code=403, detail="密钥错误")

    # 参数校验：只允许 0,1,2
    if is_merchant not in (0, 1, 2):
        raise HTTPException(status_code=400, detail="is_merchant 必须为 0、1 或 2")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE id=%s", (user_id,))
            if not cur.fetchone():
                raise HTTPException(status_code=404, detail="用户不存在")

            cur.execute("UPDATE users SET is_merchant=%s WHERE id=%s", (is_merchant, user_id))
            conn.commit()
            return {"msg": "is_merchant 已更新", "user_id": user_id, "is_merchant": is_merchant}

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

