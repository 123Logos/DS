import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from pydantic import BaseModel, Field, field_validator

from core.database import get_conn
from core.config import BASE_PIC_DIR, CATEGORY_CHOICES
from core.table_access import build_dynamic_select, get_table_structure
from pypinyin import lazy_pinyin, Style


# ProductStatus 枚举定义
class ProductStatus:
    DRAFT = 0
    ON_SALE = 1
    OFF_SALE = 2
    OUT_OF_STOCK = 3


router = APIRouter(tags=["商品管理"], responses={404: {"description": "未找到"}})


def register_routes(app):
    """注册商品管理路由到主应用"""
    from .ext import router as product_ext_router
    app.include_router(router, prefix="/api", tags=["商品管理"])
    app.include_router(product_ext_router, prefix="/api", tags=["商品管理"])


def to_pinyin(text: str) -> str:
    return " ".join(lazy_pinyin(text, style=Style.NORMAL)).upper()


PRODUCT_COLUMNS = ["id", "name", "pinyin", "description", "category",
                   "main_image", "detail_images", "status", "user_id",
                   "is_member_product", "buy_rule", "freight",
                   "created_at", "updated_at"]


def build_product_dict(product: Dict[str, Any], skus: List[Dict[str, Any]] = None,
                       attributes: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """从数据库查询结果构建商品字典（pymysql 版本）"""
    base = {col: product.get(col) for col in PRODUCT_COLUMNS}
    base["skus"] = skus or []
    base["attributes"] = attributes or []
    base["freight"] = 0.00
    # 处理 JSON 字段
    if base.get("detail_images"):
        if isinstance(base["detail_images"], str):
            try:
                base["detail_images"] = json.loads(base["detail_images"])
            except:
                base["detail_images"] = []
    return base


class SkuCreate(BaseModel):
    sku_code: str
    price: float = Field(..., ge=0)
    stock: int = Field(..., ge=0)

    @field_validator("price")
    def force_member_price(cls, v: float, info):
        return v


class ProductCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: str
    user_id: Optional[int] = None
    is_member_product: bool = False
    buy_rule: Optional[str] = None
    freight: Optional[float] = Field(0.0, ge=0, le=0, description="运费，系统强制0")
    skus: List[SkuCreate]
    attributes: Optional[List[Dict[str, str]]] = None
    status: int = Field(default=ProductStatus.DRAFT)

    @field_validator("category")
    def check_category(cls, v: str) -> str:
        if v not in CATEGORY_CHOICES:
            raise ValueError(f"非法分类，可选：{CATEGORY_CHOICES}")
        return v

    @field_validator("status")
    def check_status(cls, v: int) -> int:
        if v not in {ProductStatus.DRAFT, ProductStatus.ON_SALE, ProductStatus.OFF_SALE, ProductStatus.OUT_OF_STOCK}:
            raise ValueError(f"状态非法")
        return v


class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    status: Optional[int] = None
    user_id: Optional[int] = None
    is_member_product: Optional[bool] = None
    buy_rule: Optional[str] = None
    freight: Optional[float] = Field(None, ge=0, le=0, description="运费，系统强制0")
    attributes: Optional[List[Dict[str, str]]] = None

    @field_validator("category")
    def check_category(cls, v: Optional[str]) -> Optional[str]:
        if v and v not in CATEGORY_CHOICES:
            raise ValueError(f"非法分类，可选：{CATEGORY_CHOICES}")
        return v

    @field_validator("status")
    def check_status(cls, v: Optional[int]) -> Optional[int]:
        if v is not None and v not in {ProductStatus.DRAFT, ProductStatus.ON_SALE, ProductStatus.OFF_SALE,
                                       ProductStatus.OUT_OF_STOCK}:
            raise ValueError(f"状态非法")
        return v

# ---------------- 中文路由摘要 + 修复上下文 ----------------

@router.get("/products/search", summary="🔍 商品模糊搜索")
def search_products(
        keyword: str = Query(..., min_length=1,
                             description="搜索关键词（名称/描述/SKU/拼音/分类/商家）。同时搜索多个关键词时，请在关键词与关键词之间添加空格")
):
    """
    1. 按空格拆词，所有词必须同时命中（AND）
    2. 每个词再拆单字（OR）保证召回
    3. 不强制包含特定字，完全按关键词关联度返回
    4. 全品类返回，不影响原有环境
    """
    kw = keyword.strip()
    if not kw:
        return {"status": "success", "data": []}

    # ---------- 拆词 ----------
    words = [w for w in kw.split() if w]
    if not words:
        return {"status": "success", "data": []}

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 构建搜索条件：每个词在多个字段中搜索（OR），所有词必须同时命中（AND）
            conditions = []
            params = []

            for word in words:
                word_pattern = f"%{word}%"
                word_conditions = []
                # 搜索多个字段
                word_conditions.append("p.name LIKE %s")
                params.append(word_pattern)
                word_conditions.append("p.description LIKE %s")
                params.append(word_pattern)
                word_conditions.append("p.pinyin LIKE %s")
                params.append(word_pattern)
                word_conditions.append("p.category LIKE %s")
                params.append(word_pattern)
                word_conditions.append("ps.sku_code LIKE %s")
                params.append(word_pattern)
                word_conditions.append("u.name LIKE %s")
                params.append(word_pattern)

                # 每个词至少匹配一个字段
                conditions.append(f"({' OR '.join(word_conditions)})")

            # 所有词必须同时命中
            where_clause = " AND ".join(conditions)

            # 构建排序：同时命中全部词的置顶（通过计算匹配的字段数）
            # 简化版：按商品ID排序，实际可以优化为按匹配度排序
            sql = f"""
                SELECT DISTINCT p.*, u.name as merchant_name
                FROM products p
                INNER JOIN product_skus ps ON ps.product_id = p.id
                LEFT JOIN users u ON u.id = p.user_id
                WHERE {where_clause}
                ORDER BY p.id DESC
                LIMIT 200
            """

            cur.execute(sql, tuple(params))
            products = cur.fetchall()

            # 获取每个商品的 SKUs 和 attributes
            result_data = []
            for product in products:
                product_id = product['id']

                # 获取 SKUs
                select_sql = build_dynamic_select(
                    cur,
                    "product_skus",
                    where_clause="product_id = %s",
                    select_fields=["id", "sku_code", "price", "stock"]
                )
                cur.execute(select_sql, (product_id,))
                skus = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']), "stock": s['stock']} for
                        s in skus]

                # 获取 attributes
                select_sql = build_dynamic_select(
                    cur,
                    "product_attributes",
                    where_clause="product_id = %s",
                    select_fields=["name", "value"]
                )
                cur.execute(select_sql, (product_id,))
                attributes = cur.fetchall()
                attributes = [{"name": a['name'], "value": a['value']} for a in attributes]

                result_data.append(build_product_dict(product, skus, attributes))

            return {"status": "success", "data": result_data}


@router.get("/products", summary="📄 商品列表分页")
def get_all_products(
    category: Optional[str] = Query(None, description="分类筛选"),
    status: Optional[int] = Query(None, description="状态筛选"),
    is_member_product: Optional[int] = Query(None, description="会员商品筛选，0=非会员，1=会员", ge=0, le=1),  # ✅ 新增
    page: int = Query(1, ge=1, description="页码"),
    size: int = Query(10, ge=1, le=100, description="每页条数"),
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 构建查询条件
            where_clauses = []
            params = []

            if category:
                where_clauses.append("category = %s")
                params.append(category)
            if status is not None:
                where_clauses.append("status = %s")
                params.append(status)
            if is_member_product is not None:  # ✅ 新增逻辑
                where_clauses.append("is_member_product = %s")
                params.append(is_member_product)

            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # 查询总数
            count_sql = f"SELECT COUNT(*) as total FROM products{where_sql}"
            cur.execute(count_sql, tuple(params))
            total = cur.fetchone()['total']

            # 查询商品列表
            offset = (page - 1) * size
            sql = f"""
                SELECT * FROM products
                {where_sql}
                ORDER BY id DESC
                LIMIT %s OFFSET %s
            """
            cur.execute(sql, tuple(params + [size, offset]))
            products = cur.fetchall()

            # 获取每个商品的 SKUs 和 attributes
            result_data = []
            for product in products:
                product_id = product['id']

                # 获取 SKUs
                select_sql = build_dynamic_select(
                    cur,
                    "product_skus",
                    where_clause="product_id = %s",
                    select_fields=["id", "sku_code", "price", "stock"]
                )
                cur.execute(select_sql, (product_id,))
                skus = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']), "stock": s['stock']} for s in skus]

                # 获取 attributes
                select_sql = build_dynamic_select(
                    cur,
                    "product_attributes",
                    where_clause="product_id = %s",
                    select_fields=["name", "value"]
                )
                cur.execute(select_sql, (product_id,))
                attributes = cur.fetchall()
                attributes = [{"name": a['name'], "value": a['value']} for a in attributes]

                result_data.append(build_product_dict(product, skus, attributes))

            return {"status": "success", "total": total, "page": page, "size": size, "data": result_data}


@router.get("/products/{id}", summary="📦 查询单个商品")
def get_product(id: int):
    with get_conn() as conn:
        with conn.cursor() as cur:
            # 查询商品
            select_sql = build_dynamic_select(
                cur,
                "products",
                where_clause="id = %s"
            )
            cur.execute(select_sql, (id,))
            product = cur.fetchone()
            if not product:
                raise HTTPException(status_code=404, detail="商品不存在")

            # 获取 SKUs
            select_sql = build_dynamic_select(
                cur,
                "product_skus",
                where_clause="product_id = %s",
                select_fields=["id", "sku_code", "price", "stock"]
            )
            cur.execute(select_sql, (id,))
            skus = cur.fetchall()
            skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']), "stock": s['stock']} for s in
                    skus]

            # 获取 attributes
            select_sql = build_dynamic_select(
                cur,
                "product_attributes",
                where_clause="product_id = %s",
                select_fields=["name", "value"]
            )
            cur.execute(select_sql, (id,))
            attributes = cur.fetchall()
            attributes = [{"name": a['name'], "value": a['value']} for a in attributes]

            return {"status": "success", "data": build_product_dict(product, skus, attributes)}


@router.post("/products", summary="➕ 新增商品")
def add_product(payload: ProductCreate):
    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 处理会员商品价格
                sku_prices = []
                for sku in payload.skus:
                    if payload.is_member_product:
                        sku_prices.append(1980.0)
                    else:
                        sku_prices.append(sku.price)

                # 插入商品
                pinyin = to_pinyin(payload.name)
                cur.execute("""
                    INSERT INTO products (name, pinyin, description, category, status, user_id, 
                                        is_member_product, buy_rule, freight)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    payload.name, pinyin, payload.description, payload.category, payload.status,
                    payload.user_id, payload.is_member_product, payload.buy_rule, 0.0
                ))
                product_id = cur.lastrowid

                # 插入 SKUs
                for sku, price in zip(payload.skus, sku_prices):
                    cur.execute("""
                        INSERT INTO product_skus (product_id, sku_code, price, stock)
                        VALUES (%s, %s, %s, %s)
                    """, (product_id, sku.sku_code, price, sku.stock))

                # 插入 attributes
                if payload.attributes:
                    for attr in payload.attributes:
                        cur.execute("""
                            INSERT INTO product_attributes (product_id, name, value)
                            VALUES (%s, %s, %s)
                        """, (product_id, attr["name"], attr["value"]))

                conn.commit()

                # 查询创建的商品
                select_sql = build_dynamic_select(
                    cur,
                    "products",
                    where_clause="id = %s"
                )
                cur.execute(select_sql, (product_id,))
                product = cur.fetchone()

                # 获取 SKUs
                select_sql = build_dynamic_select(
                    cur,
                    "product_skus",
                    where_clause="product_id = %s",
                    select_fields=["id", "sku_code", "price", "stock"]
                )
                cur.execute(select_sql, (product_id,))
                skus = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']), "stock": s['stock']} for
                        s in skus]

                # 获取 attributes
                select_sql = build_dynamic_select(
                    cur,
                    "product_attributes",
                    where_clause="product_id = %s",
                    select_fields=["name", "value"]
                )
                cur.execute(select_sql, (product_id,))
                attributes = cur.fetchall()
                attributes = [{"name": a['name'], "value": a['value']} for a in attributes]

                return {"status": "success", "message": "商品已创建",
                        "data": build_product_dict(product, skus, attributes)}
            except Exception as e:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"创建商品失败: {str(e)}")


@router.put("/products/{id}", summary="✏️ 更新商品")
def update_product(id: int, payload: ProductUpdate):
    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 检查商品是否存在
                select_sql = build_dynamic_select(
                    cur,
                    "products",
                    where_clause="id = %s"
                )
                cur.execute(select_sql, (id,))
                product = cur.fetchone()
                if not product:
                    raise HTTPException(status_code=404, detail="商品不存在")

                # 构建更新字段
                update_fields = []
                update_params = []

                update_data = payload.dict(exclude_unset=True, exclude={"attributes"})
                # ✅ 禁止修改 is_member_product 字段
                update_data.pop("is_member_product", None)

                for key, value in update_data.items():
                    if key == "freight":
                        value = 0.0
                    if value is not None:
                        update_fields.append(f"{key} = %s")
                        update_params.append(value)

                # 更新商品
                if update_fields:
                    update_params.append(id)
                    cur.execute(f"""
                        UPDATE products 
                        SET {', '.join(update_fields)}, updated_at = NOW()
                        WHERE id = %s
                    """, tuple(update_params))

                # 更新 attributes
                if payload.attributes is not None:
                    # 删除旧 attributes
                    cur.execute("DELETE FROM product_attributes WHERE product_id = %s", (id,))
                    # 插入新 attributes
                    for attr in payload.attributes:
                        cur.execute("""
                            INSERT INTO product_attributes (product_id, name, value)
                            VALUES (%s, %s, %s)
                        """, (id, attr["name"], attr["value"]))

                conn.commit()

                # 查询更新后的商品
                select_sql = build_dynamic_select(
                    cur,
                    "products",
                    where_clause="id = %s"
                )
                cur.execute(select_sql, (id,))
                updated_product = cur.fetchone()

                # 获取 SKUs
                select_sql = build_dynamic_select(
                    cur,
                    "product_skus",
                    where_clause="product_id = %s",
                    select_fields=["id", "sku_code", "price", "stock"]
                )
                cur.execute(select_sql, (id,))
                skus = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']), "stock": s['stock']} for
                        s in skus]

                # 获取 attributes
                select_sql = build_dynamic_select(
                    cur,
                    "product_attributes",
                    where_clause="product_id = %s",
                    select_fields=["name", "value"]
                )
                cur.execute(select_sql, (id,))
                attributes = cur.fetchall()
                attributes = [{"name": a['name'], "value": a['value']} for a in attributes]

                return {"status": "success", "message": "商品已更新",
                        "data": build_product_dict(updated_product, skus, attributes)}
            except HTTPException:
                raise
            except Exception as e:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"更新商品失败: {str(e)}")


@router.post("/products/{id}/images", summary="📸 上传商品图片")
def upload_images(
        id: int,
        detail_images: List[UploadFile] = File([], description="详情图，最多10张，单张<3MB，仅JPG/PNG/WEBP"),
        banner_images: List[UploadFile] = File([], description="轮播图，最多10张，单张<5MB，仅JPG/PNG/WEBP"),
):
    from PIL import Image
    import uuid

    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 查询商品
                select_sql = build_dynamic_select(
                    cur,
                    "products",
                    where_clause="id = %s"
                )
                cur.execute(select_sql, (id,))
                product = cur.fetchone()
                if not product:
                    raise HTTPException(status_code=404, detail="商品不存在")

                category = product['category']
                cat_path = BASE_PIC_DIR / category
                goods_path = cat_path / str(id)
                goods_path.mkdir(parents=True, exist_ok=True)

                detail_urls = []
                if detail_images:
                    if len(detail_images) > 10:
                        raise HTTPException(status_code=400, detail="详情图最多10张")
                    for f in detail_images:
                        ext = Path(f.filename).suffix.lower()
                        if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                            raise HTTPException(status_code=400, detail="仅支持 JPG/PNG/WEBP")
                        if f.size > 3 * 1024 * 1024:
                            raise HTTPException(status_code=400, detail="详情图单张大小不能超过 3MB")
                        file_name = f"detail_{uuid.uuid4().hex}{ext}"
                        file_path = goods_path / file_name
                        with Image.open(f.file) as im:
                            im = im.convert("RGB")
                            im.thumbnail((750, 2000), Image.LANCZOS)
                            im.save(file_path, "JPEG", quality=80, optimize=True)
                        detail_urls.append(f"/pic/{category}/{id}/{file_name}")

                    # 更新商品详情图
                    cur.execute("UPDATE products SET detail_images = %s WHERE id = %s",
                                (json.dumps(detail_urls, ensure_ascii=False), id))

                banner_urls = []
                if banner_images:
                    if len(banner_images) > 10:
                        raise HTTPException(status_code=400, detail="轮播图最多10张")
                    # 删除旧轮播图
                    cur.execute("DELETE FROM banner WHERE product_id = %s", (id,))

                    for idx, f in enumerate(banner_images):
                        ext = Path(f.filename).suffix.lower()
                        if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                            raise HTTPException(status_code=400, detail="仅支持 JPG/PNG/WEBP")
                        if f.size > 5 * 1024 * 1024:
                            raise HTTPException(status_code=400, detail="轮播图单张大小不能超过 5MB")
                        file_name = f"banner_{uuid.uuid4().hex}{ext}"
                        file_path = goods_path / file_name
                        with Image.open(f.file) as im:
                            im = im.convert("RGB")
                            im.thumbnail((1200, 1200), Image.LANCZOS)
                            im.save(file_path, "JPEG", quality=85, optimize=True)
                        url = f"/pic/{category}/{id}/{file_name}"
                        banner_urls.append(url)
                        cur.execute("""
                            INSERT INTO banner (product_id, image_url, sort_order, status)
                            VALUES (%s, %s, %s, %s)
                        """, (id, url, idx, 1))

                    # 更新商品主图
                    if banner_urls:
                        cur.execute("UPDATE products SET main_image = %s WHERE id = %s",
                                    (banner_urls[0], id))

                conn.commit()

                # 查询更新后的商品
                select_sql = build_dynamic_select(
                    cur,
                    "products",
                    where_clause="id = %s"
                )
                cur.execute(select_sql, (id,))
                updated_product = cur.fetchone()

                # 获取 SKUs
                select_sql = build_dynamic_select(
                    cur,
                    "product_skus",
                    where_clause="product_id = %s",
                    select_fields=["id", "sku_code", "price", "stock"]
                )
                cur.execute(select_sql, (id,))
                skus = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']), "stock": s['stock']} for
                        s in skus]

                # 获取 attributes
                select_sql = build_dynamic_select(
                    cur,
                    "product_attributes",
                    where_clause="product_id = %s",
                    select_fields=["name", "value"]
                )
                cur.execute(select_sql, (id,))
                attributes = cur.fetchall()
                attributes = [{"name": a['name'], "value": a['value']} for a in attributes]

                return {"status": "success", "message": "图片上传完成",
                        "data": build_product_dict(updated_product, skus, attributes)}
            except HTTPException:
                raise
            except Exception as e:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"上传图片失败: {str(e)}")


@router.get("/banners", summary="🖼️ 轮播图列表")
def get_banners(product_id: Optional[int] = Query(None, description="商品ID，留空返回全部")):
    with get_conn() as conn:
        with conn.cursor() as cur:
            if product_id:
                cur.execute("""
                    SELECT * FROM banner
                    WHERE status = 1 AND product_id = %s
                    ORDER BY sort_order
                """, (product_id,))
            else:
                cur.execute("""
                    SELECT * FROM banner
                    WHERE status = 1
                    ORDER BY sort_order
                """)
            banners = cur.fetchall()
            return {"status": "success", "data": banners}


@router.get("/products/{id}/sales", summary="📊 商品销售数据")
def get_sales_data(id: int):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT SUM(quantity) AS qty, SUM(total_price) AS sales FROM order_items WHERE product_id=%s",
                (id,)
            )
            row = cur.fetchone()
            if not row or not row.get('qty'):
                raise HTTPException(status_code=404, detail="暂无销售数据")
            return {"status": "success",
                    "data": {"total_quantity": int(row['qty']), "total_sales": float(row['sales'])}}