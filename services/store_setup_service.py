import logging
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from fastapi import UploadFile, HTTPException
from core.database import get_conn
from core.table_access import build_dynamic_select
from core.exceptions import FinanceException
from core.config import BASE_PIC_DIR
from PIL import Image
from models.schemas.store_setup import (
    StoreInfoCreateReq, StoreInfoUpdateReq, StoreLogoUploadResp
)

logger = logging.getLogger(__name__)


class StoreSetupService:
    """店铺设置服务类"""

    def __init__(self):
        self.logo_max_size = 5 * 1024 * 1024  # 5MB
        self.logo_max_dimension = (500, 500)  # 最大500x500
        self.allowed_extensions = {".jpg", ".jpeg", ".png", ".webp"}

    def _check_user_exists(self, user_id: int) -> bool:
        """检查用户是否存在"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                sql = build_dynamic_select(cur, "users", where_clause="id=%s", select_fields=["id"])
                cur.execute(sql, (user_id,))
                return cur.fetchone() is not None

    def _check_permission(self, user_id: int) -> bool:
        """检查是否有开店权限（支付进件成功）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                sql = build_dynamic_select(cur, "users", where_clause="id=%s", select_fields=["has_store_permission"])
                cur.execute(sql, (user_id,))
                result = cur.fetchone()
                return result and result['has_store_permission'] == 1

    def create_store_info(self, req: StoreInfoCreateReq) -> Dict[str, Any]:
        """创建店铺信息（支付进件成功后调用）"""
        if not self._check_user_exists(req.user_id):
            raise FinanceException(f"用户不存在: user_id={req.user_id}")

        if not self._check_permission(req.user_id):
            raise FinanceException("请先完成支付进件，开通开店权限")

        # 检查是否已存在店铺信息
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM merchant_stores WHERE user_id=%s",
                    (req.user_id,)
                )
                existing = cur.fetchone()

                if existing:
                    raise FinanceException("店铺信息已存在，请使用更新接口")

                sql = """
                    INSERT INTO merchant_stores (
                        user_id, store_name, store_logo_image_id, store_description,
                        contact_name, contact_phone, contact_email, business_hours, store_address
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                # ✅ 修复：使用 cur.execute + cur.lastrowid
                cur.execute(sql, (
                    req.user_id, req.store_name, req.store_logo_image_id,
                    req.store_description, req.contact_name, req.contact_phone,
                    req.contact_email, req.business_hours, req.store_address
                ))
                store_id = cur.lastrowid

                # 设置用户为商家
                cur.execute(
                    "UPDATE users SET is_merchant=1 WHERE id=%s",
                    (req.user_id,)
                )

                conn.commit()

        logger.info(f"店铺信息创建成功: user_id={req.user_id}, store_id={store_id}")
        return {"store_id": store_id, "message": "店铺信息创建成功"}

    def update_store_info(self, user_id: int, req: StoreInfoUpdateReq) -> Dict[str, Any]:
        """更新店铺信息"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT id FROM merchant_stores WHERE user_id=%s",
                    (user_id,)
                )
                store = cur.fetchone()

                if not store:
                    raise FinanceException("店铺信息不存在")

                update_fields = []
                params = []

                if req.store_name is not None:
                    update_fields.append("store_name=%s")
                    params.append(req.store_name)
                if req.store_logo_image_id is not None:
                    update_fields.append("store_logo_image_id=%s")
                    params.append(req.store_logo_image_id)
                if req.store_description is not None:
                    update_fields.append("store_description=%s")
                    params.append(req.store_description)
                if req.contact_name is not None:
                    update_fields.append("contact_name=%s")
                    params.append(req.contact_name)
                if req.contact_phone is not None:
                    update_fields.append("contact_phone=%s")
                    params.append(req.contact_phone)
                if req.contact_email is not None:
                    update_fields.append("contact_email=%s")
                    params.append(req.contact_email)
                if req.business_hours is not None:
                    update_fields.append("business_hours=%s")
                    params.append(req.business_hours)
                if req.store_address is not None:
                    update_fields.append("store_address=%s")
                    params.append(req.store_address)

                if not update_fields:
                    return {"message": "无更新内容"}

                params.append(user_id)
                sql = f"""
                    UPDATE merchant_stores 
                    SET {', '.join(update_fields)}, updated_at=NOW() 
                    WHERE user_id=%s
                """
                cur.execute(sql, params)
                conn.commit()

        logger.info(f"店铺信息更新成功: user_id={user_id}")
        return {"message": "店铺信息更新成功"}

    def get_store_info(self, user_id: int) -> Optional[Dict[str, Any]]:
        """获取店铺信息"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # ✅ 修复：使用 id AS store_id 别名，匹配 Pydantic 模型
                cur.execute(
                    """
                    SELECT 
                        id AS store_id,
                        user_id,
                        store_name,
                        store_logo_image_id,
                        store_description,
                        contact_name,
                        contact_phone,
                        contact_email,
                        business_hours,
                        store_address,
                        created_at,
                        updated_at
                    FROM merchant_stores 
                    WHERE user_id=%s
                    """,
                    (user_id,)
                )
                store = cur.fetchone()

                if not store:
                    return None

                # 生成LOGO URL
                if store.get('store_logo_image_id'):
                    store['store_logo_url'] = f"/api/store/logo/preview/{store['store_logo_image_id']}"

                return store

    def get_setup_status(self, user_id: int) -> Dict[str, Any]:
        """获取店铺设置状态（支付进件和店铺信息）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查支付进件状态（has_store_permission）
                cur.execute(
                    "SELECT has_store_permission, is_merchant FROM users WHERE id=%s",
                    (user_id,)
                )
                user = cur.fetchone()

                if not user:
                    raise FinanceException(f"用户不存在: user_id={user_id}")

                has_store_permission = user['has_store_permission'] == 1
                has_payment_account = has_store_permission
                is_merchant = user['is_merchant'] == 1

                # 检查是否已设置店铺信息
                cur.execute(
                    "SELECT id FROM merchant_stores WHERE user_id=%s",
                    (user_id,)
                )
                store = cur.fetchone()

                has_store_info = store is not None
                can_setup_store = has_store_permission and not has_store_info

                return {
                    "user_id": user_id,
                    "has_store_permission": has_store_permission,
                    "has_payment_account": has_payment_account,
                    "has_store_info": has_store_info,
                    "can_setup_store": can_setup_store,
                    "store_info": self.get_store_info(user_id) if has_store_info else None
                }

    def upload_store_logo(self, user_id: int, file: UploadFile) -> StoreLogoUploadResp:
        """
        仿照头像上传功能，但适配店铺LOGO业务：
        1. 只支持单张（店铺只有一个LOGO）
        2. 单张 ≤5MB
        3. 统一压缩、重命名、返回image_id和URL
        4. 支持覆盖更新（新logo替换旧logo）
        """
        # 1. 大小校验
        if file.size > self.logo_max_size:
            raise HTTPException(status_code=400, detail=f"LOGO文件大小不能超过{self.logo_max_size // 1024 // 1024}MB")

        # 2. 格式校验
        ext = Path(file.filename).suffix.lower()
        if ext not in self.allowed_extensions:
            raise HTTPException(status_code=400, detail="仅支持 JPG/PNG/WEBP 格式")

        # 3. 生成唯一文件名
        image_id = f"store_logo_{user_id}_{uuid.uuid4().hex}{ext}"

        # 4. 确定存储路径
        logo_dir = BASE_PIC_DIR / "store_logos"
        logo_dir.mkdir(parents=True, exist_ok=True)
        file_path = logo_dir / image_id

        # 5. 图片处理（仿照头像压缩逻辑）
        try:
            with Image.open(file.file) as im:
                im = im.convert("RGB")
                # 保持宽高比缩放
                im.thumbnail(self.logo_max_dimension, Image.LANCZOS)

                # 保存为JPEG格式，确保兼容性
                im.save(file_path, "JPEG", quality=85, optimize=True)

                # 计算压缩后文件大小
                file_size = file_path.stat().st_size
        except Exception as e:
            logger.error(f"LOGO图片处理失败: {str(e)}")
            raise HTTPException(status_code=500, detail="图片处理失败")

        # 6. 保存到数据库（仿照头像写库逻辑）
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 先删除旧的LOGO记录（覆盖更新）
                cur.execute(
                    "DELETE FROM store_logos WHERE user_id = %s",
                    (user_id,)
                )

                # 插入新LOGO记录
                sql = """
                    INSERT INTO store_logos (
                        image_id, user_id, file_path, file_size, upload_time
                    ) VALUES (%s, %s, %s, %s, NOW())
                """
                cur.execute(sql, (image_id, user_id, str(file_path), file_size))

                # 更新店铺表中的logo引用
                cur.execute(
                    "UPDATE merchant_stores SET store_logo_image_id = %s, updated_at = NOW() WHERE user_id = %s",
                    (image_id, user_id)
                )

                conn.commit()

        logger.info(f"店铺LOGO上传成功: user_id={user_id}, image_id={image_id}")

        # 7. 返回结果
        return StoreLogoUploadResp(
            image_id=image_id,
            image_url=f"/api/store/logo/preview/{image_id}",  # 使用相对路径
            file_size=file_size
        )

    def delete_store_logo(self, user_id: int) -> None:
        """删除店铺LOGO（可选功能）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 查询当前LOGO
                cur.execute("SELECT image_id, file_path FROM store_logos WHERE user_id = %s", (user_id,))
                logo = cur.fetchone()

                if logo:
                    # 删除物理文件
                    import os
                    try:
                        os.remove(logo['file_path'])
                    except FileNotFoundError:
                        pass

                    # 删除数据库记录
                    cur.execute("DELETE FROM store_logos WHERE user_id = %s", (user_id,))

                    # 清空店铺表的引用
                    cur.execute(
                        "UPDATE merchant_stores SET store_logo_image_id = NULL, updated_at = NOW() WHERE user_id = %s",
                        (user_id,)
                    )

                    conn.commit()
                    logger.info(f"店铺LOGO删除成功: user_id={user_id}")


class StoreAdminService:
    """店铺管理后台服务"""

    def get_store_list(self, page: int = 1, page_size: int = 10) -> Dict[str, Any]:
        """获取店铺列表（管理后台）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                count_sql = "SELECT COUNT(*) as total FROM merchant_stores"
                cur.execute(count_sql)
                total = cur.fetchone()['total']

                sql = """
                    SELECT 
                        ms.id, ms.user_id, u.name as user_name, ms.store_name,
                        ms.store_logo_image_id, ms.contact_phone, ms.created_at,
                        ms.updated_at
                    FROM merchant_stores ms
                    JOIN users u ON ms.user_id = u.id
                    ORDER BY ms.created_at DESC
                    LIMIT %s OFFSET %s
                """
                cur.execute(sql, (page_size, (page - 1) * page_size))
                items = cur.fetchall()

                return {"total": total, "items": items}