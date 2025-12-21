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


# ✅ 新增：处理可选文件上传的依赖函数
def get_optional_files(files: Optional[List[UploadFile]] = File(None)) -> Optional[List[UploadFile]]:
    """
    处理可选文件上传参数，解决422错误
    - 过滤掉前端发送的空字符串等无效文件对象
    - 保持原有上传逻辑完全不变
    """
    if files is None:
        return None

    # 过滤掉无效的文件项（包括空字符串、None等）
    valid_files = [f for f in files if f is not None and hasattr(f, 'filename') and f.filename]
    return valid_files if valid_files else None


# ✅ 修改：在 PRODUCT_COLUMNS 中添加 max_points_discount
PRODUCT_COLUMNS = ["id", "name", "pinyin", "description", "category",
                   "main_image", "detail_images", "status", "user_id",
                   "is_member_product", "buy_rule", "freight",
                   "created_at", "updated_at", "max_points_discount"]


def build_product_dict(product: Dict[str, Any], skus: List[Dict[str, Any]] = None,
                       attributes: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """从数据库查询结果构建商品字典（pymysql 版本）"""
    base = {col: product.get(col) for col in PRODUCT_COLUMNS}
    base["skus"] = skus or []
    base["attributes"] = attributes or []
    base["freight"] = 0.00

    # ✅ 新增：如果查询结果包含商家名称，添加到返回数据中
    if 'merchant_name' in product and product['merchant_name']:
        base['merchant_name'] = product['merchant_name']

    # 处理 JSON 字段
    if base.get("detail_images"):
        if isinstance(base["detail_images"], str):
            try:
                base["detail_images"] = json.loads(base["detail_images"])
            except:
                base["detail_images"] = []
    # 兼容 main_image 既可能为单个字符串也可能为 JSON 列表的情况
    if base.get("main_image"):
        mi = base["main_image"]
        try:
            if isinstance(mi, str) and mi.strip().startswith("["):
                parsed = json.loads(mi)
                if isinstance(parsed, list):
                    base["banner_images"] = parsed
                    base["main_image"] = parsed[0] if parsed else None
                else:
                    base["banner_images"] = []
            else:
                base["banner_images"] = []
        except Exception:
            base["banner_images"] = []

    # ✅ 新增：处理SKU的specifications字段
    if base.get("skus"):
        for sku in base["skus"]:
            if sku.get("specifications") and isinstance(sku["specifications"], str):
                try:
                    sku["specifications"] = json.loads(sku["specifications"])
                except:
                    sku["specifications"] = {}

    return base


class SkuCreate(BaseModel):
    sku_code: str
    price: float = Field(..., ge=0)  # 商品现价
    # ✅ 新增字段：商品原价
    original_price: Optional[float] = Field(None, ge=0)
    # ✅ 新增字段：商品规格
    specifications: Optional[Dict[str, Any]] = None
    stock: int = Field(..., ge=0)

    @field_validator("price")
    def force_member_price(cls, v: float, info):
        return v


# ✅ 新增：SKU更新模型（必须提供id）
class SkuUpdate(BaseModel):
    id: int  # 必须提供SKU的ID来定位记录
    sku_code: Optional[str] = None
    price: Optional[float] = Field(None, ge=0)
    original_price: Optional[float] = Field(None, ge=0)
    stock: Optional[int] = Field(None, ge=0)
    specifications: Optional[Dict[str, Any]] = None


class ProductCreate(BaseModel):
    name: str
    description: Optional[str] = None
    category: str
    user_id: Optional[int] = None
    is_member_product: bool = False
    buy_rule: Optional[str] = None
    freight: Optional[float] = Field(0.0, ge=0, le=0, description="运费，系统强制0")
    # ✅ 新增字段：积分抵扣上限
    max_points_discount: Optional[float] = Field(None, ge=0, description="积分抵扣上限")
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


# ✅ 修改：ProductUpdate 添加 skus 字段
class ProductUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    status: Optional[int] = None
    user_id: Optional[int] = None
    is_member_product: Optional[bool] = None  # ✅ 允许修改会员商品状态
    buy_rule: Optional[str] = None
    freight: Optional[float] = Field(None, ge=0, le=0, description="运费，系统强制0")
    # ✅ 新增字段：积分抵扣上限
    max_points_discount: Optional[float] = Field(None, ge=0, description="积分抵扣上限")
    # ✅ 新增：支持更新SKU列表
    skus: Optional[List[SkuUpdate]] = None
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


# ✅ 新增：删除图片请求模型
class ImageDeleteRequest(BaseModel):
    image_urls: List[str]
    image_type: str = Field(..., pattern="^(banner|detail)$")  # ✅ 修改：regex → pattern


# ✅ 新增：更新图片请求模型
class ImageUpdateRequest(BaseModel):
    detail_images: Optional[List[str]] = None
    banner_images: Optional[List[str]] = None


# ---------------- 中文路由摘要 + 修复上下文 ----------------

@router.get("/products/search", summary="🔍 商品模糊搜索")
def search_products(
        keyword: str = Query(..., min_length=1,
                             description="搜索关键词（名称/描述/SKU/拼音/分类/商家/属性值）。同时搜索多个关键词时，请在关键词与关键词之间添加空格")
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

                # ✅ 修改：只搜索商品属性值，不搜索属性名
                word_conditions.append("pa.value LIKE %s")
                params.append(word_pattern)

                # 每个词至少匹配一个字段
                conditions.append(f"({' OR '.join(word_conditions)})")

            # 所有词必须同时命中
            where_clause = " AND ".join(conditions)

            # 构建排序：同时命中全部词的置顶（通过计算匹配的字段数）
            # 简化版：按商品ID排序，实际可以优化为按匹配度排序
            # ✅ 修改：添加 LEFT JOIN product_attributes 表（仅用于搜索value）
            sql = f"""
                SELECT DISTINCT p.*, u.name as merchant_name
                FROM products p
                INNER JOIN product_skus ps ON ps.product_id = p.id
                LEFT JOIN product_attributes pa ON pa.product_id = p.id  -- ✅ 仅用于搜索value
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
                    # ✅ 修改：查询新增字段 original_price 和 specifications
                    select_fields=["id", "sku_code", "price", "original_price", "stock", "specifications"]
                )
                cur.execute(select_sql, (product_id,))
                skus = cur.fetchall()
                # ✅ 修改：格式化新增字段
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']),
                         "original_price": float(s['original_price']) if s['original_price'] else None,
                         "stock": s['stock'], "specifications": s['specifications']} for s in skus]

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
        is_member_product: Optional[int] = Query(None, description="会员商品筛选，0=非会员，1=会员", ge=0, le=1),
        user_id: Optional[int] = Query(None, description="商家ID筛选"),  # ✅ 新增：支持按商家筛选
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
            if is_member_product is not None:
                where_clauses.append("is_member_product = %s")
                params.append(is_member_product)
            if user_id is not None:  # ✅ 新增：支持按商家筛选
                where_clauses.append("user_id = %s")
                params.append(user_id)

            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            # 查询总数
            count_sql = f"SELECT COUNT(*) as total FROM products{where_sql}"
            cur.execute(count_sql, tuple(params))
            total = cur.fetchone()['total']

            # 查询商品列表 - 使用动态表访问
            offset = (page - 1) * size
            where_clause_clean = " AND ".join(where_clauses) if where_clauses else None
            # 构建基础 SQL（不包含 LIMIT）
            select_sql_base = build_dynamic_select(
                cur,
                "products",
                where_clause=where_clause_clean,
                order_by="id DESC"
            )
            # 添加 LIMIT 和 OFFSET（使用参数化查询）
            select_sql = f"{select_sql_base} LIMIT %s OFFSET %s"
            cur.execute(select_sql, tuple(params + [size, offset]))
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
                    # ✅ 修改：查询新增字段 original_price 和 specifications
                    select_fields=["id", "sku_code", "price", "original_price", "stock", "specifications"]
                )
                cur.execute(select_sql, (product_id,))
                skus = cur.fetchall()
                # ✅ 修改：格式化新增字段
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']),
                         "original_price": float(s['original_price']) if s['original_price'] else None,
                         "stock": s['stock'], "specifications": s['specifications']} for s in skus]

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
                # ✅ 修改：查询新增字段 original_price 和 specifications
                select_fields=["id", "sku_code", "price", "original_price", "stock", "specifications"]
            )
            cur.execute(select_sql, (id,))
            skus = cur.fetchall()
            # ✅ 修改：格式化新增字段
            skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']),
                     "original_price": float(s['original_price']) if s['original_price'] else None,
                     "stock": s['stock'], "specifications": s['specifications']} for s in skus]

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
                # 处理会员商品价格: 强制所有SKU价格为1980
                sku_prices = []
                for sku in payload.skus:
                    if payload.is_member_product:
                        sku_prices.append(1980.0)  # 会员商品强制1980
                    else:
                        sku_prices.append(sku.price)

                # 插入商品
                pinyin = to_pinyin(payload.name)
                cur.execute("""
                    INSERT INTO products (name, pinyin, description, category, status, user_id, 
                                        is_member_product, buy_rule, freight, max_points_discount)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    payload.name, pinyin, payload.description, payload.category, payload.status,
                    payload.user_id, payload.is_member_product, payload.buy_rule, 0.0,
                    payload.max_points_discount
                ))
                product_id = cur.lastrowid

                # 插入 SKUs
                for sku, price in zip(payload.skus, sku_prices):
                    cur.execute("""
                        INSERT INTO product_skus (product_id, sku_code, price, original_price, stock, specifications)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        product_id,
                        sku.sku_code,
                        price,  # 会员商品此时为1980
                        sku.original_price,
                        sku.stock,
                        json.dumps(sku.specifications, ensure_ascii=False) if sku.specifications else None
                    ))

                # 插入 attributes
                if payload.attributes:
                    for attr in payload.attributes:
                        # 兼容前端两种传参格式：{"name":"...","value":"..."} 或 {"key":"value"}
                        if isinstance(attr, dict) and "name" in attr and "value" in attr:
                            a_name = attr["name"]
                            a_value = attr["value"]
                        elif isinstance(attr, dict) and len(attr) >= 1:
                            # 取第一个键值作为 name/value
                            k, v = next(iter(attr.items()))
                            a_name = k
                            a_value = v
                        else:
                            a_name = None
                            a_value = None
                        cur.execute("""
                            INSERT INTO product_attributes (product_id, name, value)
                            VALUES (%s, %s, %s)
                        """, (product_id, a_name, a_value))

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
                    select_fields=["id", "sku_code", "price", "original_price", "stock", "specifications"]
                )
                cur.execute(select_sql, (product_id,))
                skus = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']),
                         "original_price": float(s['original_price']) if s['original_price'] else None,
                         "stock": s['stock'], "specifications": s['specifications']} for s in skus]

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


# ✅ 重写：支持SKU更新的商品更新接口（灵活控制会员商品价格）
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

                # 获取当前商品的会员状态
                current_is_member = bool(product.get('is_member_product', 0))
                new_is_member = payload.is_member_product

                # 构建商品更新字段
                update_fields = []
                update_params = []

                update_data = payload.dict(exclude_unset=True, exclude={"attributes", "skus"})

                for key, value in update_data.items():
                    if key == "freight":
                        value = 0.0
                    if value is not None:
                        update_fields.append(f"{key} = %s")
                        update_params.append(value)

                # 更新商品基本信息
                if update_fields:
                    update_params.append(id)
                    cur.execute(f"""
                        UPDATE products 
                        SET {', '.join(update_fields)}, updated_at = NOW()
                        WHERE id = %s
                    """, tuple(update_params))

                # ✅ 灵活处理SKU价格：如果商品是会员商品且变为会员商品，强制1980
                # 但如果提供了skus参数，则使用提供的价
                if new_is_member is True and not payload.skus:
                    # 如果没有提供SKU更新，但设置为会员商品，则将所有SKU价格改为1980
                    cur.execute("""
                        UPDATE product_skus 
                        SET price = 1980.00, updated_at = NOW()
                        WHERE product_id = %s
                    """, (id,))
                elif payload.skus is not None:
                    # 提供了SKU更新参数，灵活控制价格
                    for sku_update in payload.skus:
                        if not sku_update.id:
                            continue

                        sku_fields = []
                        sku_params = []

                        if sku_update.sku_code is not None:
                            sku_fields.append("sku_code = %s")
                            sku_params.append(sku_update.sku_code)

                        # ✅ 会员商品价格可灵活修改：如果提供了price则修改，否则保持原样
                        if sku_update.price is not None:
                            sku_fields.append("price = %s")
                            sku_params.append(sku_update.price)

                        if sku_update.original_price is not None:
                            sku_fields.append("original_price = %s")
                            sku_params.append(sku_update.original_price)
                        if sku_update.stock is not None:
                            sku_fields.append("stock = %s")
                            sku_params.append(sku_update.stock)
                        if sku_update.specifications is not None:
                            sku_fields.append("specifications = %s")
                            sku_params.append(json.dumps(sku_update.specifications, ensure_ascii=False))

                        if sku_fields:
                            # 验证SKU属于该商品
                            cur.execute("SELECT 1 FROM product_skus WHERE id = %s AND product_id = %s",
                                        (sku_update.id, id))
                            if not cur.fetchone():
                                raise HTTPException(status_code=400, detail=f"SKU ID {sku_update.id} 不属于商品 {id}")

                            sku_params.extend([sku_update.id, id])
                            cur.execute(f"""
                                UPDATE product_skus 
                                SET {', '.join(sku_fields)}, updated_at = NOW()
                                WHERE id = %s AND product_id = %s
                            """, tuple(sku_params))

                # 更新 attributes
                if payload.attributes is not None:
                    # 删除旧 attributes
                    cur.execute("DELETE FROM product_attributes WHERE product_id = %s", (id,))
                    # 插入新 attributes（兼容多种格式）
                    for attr in payload.attributes:
                        if isinstance(attr, dict) and "name" in attr and "value" in attr:
                            a_name = attr["name"]
                            a_value = attr["value"]
                        elif isinstance(attr, dict) and len(attr) >= 1:
                            k, v = next(iter(attr.items()))
                            a_name = k
                            a_value = v
                        else:
                            a_name = None
                            a_value = None
                        cur.execute("""
                            INSERT INTO product_attributes (product_id, name, value)
                            VALUES (%s, %s, %s)
                        """, (id, a_name, a_value))

                conn.commit()

                # 查询更新后的商品
                select_sql = build_dynamic_select(
                    cur,
                    "products",
                    where_clause="id = %s"
                )
                cur.execute(select_sql, (id,))
                updated_product = cur.fetchone()

                # 获取所有 SKUs
                select_sql = build_dynamic_select(
                    cur,
                    "product_skus",
                    where_clause="product_id = %s",
                    select_fields=["id", "sku_code", "price", "original_price", "stock", "specifications"]
                )
                cur.execute(select_sql, (id,))
                skus = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']),
                         "original_price": float(s['original_price']) if s['original_price'] else None,
                         "stock": s['stock'], "specifications": s['specifications']} for s in skus]

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

                return {"status": "success", "message": "商品及SKU已更新",
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

                # 初始化 detail_urls：若数据库中已有详情图则使用，否则设为 []
                raw_detail = product.get('detail_images')
                try:
                    if raw_detail:
                        if isinstance(raw_detail, str):
                            detail_urls = json.loads(raw_detail)
                        elif isinstance(raw_detail, list):
                            detail_urls = raw_detail
                        else:
                            detail_urls = []
                    else:
                        detail_urls = []
                except Exception:
                    detail_urls = []

                # ✅ 修改：读取现有的轮播图列表（用于追加，而非覆盖）
                # 第一次上传时会初始化空列表，后续上传会读取已有图片并追加
                raw_main = product.get('main_image')
                banner_urls = []
                try:
                    if raw_main:
                        if isinstance(raw_main, str) and raw_main.strip().startswith('['):
                            banner_urls = json.loads(raw_main)
                        elif isinstance(raw_main, list):
                            banner_urls = raw_main
                except Exception:
                    banner_urls = []

                category = product['category']
                cat_path = BASE_PIC_DIR / category
                goods_path = cat_path / str(id)
                goods_path.mkdir(parents=True, exist_ok=True)

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

                if banner_images:
                    if len(banner_images) > 10:
                        raise HTTPException(status_code=400, detail="轮播图最多10张")

                    # ✅ 修改：将上传的轮播图文件保存并追加到 banner_urls 列表
                    # 同时插入到 banner 表，实现追加逻辑而非覆盖
                    for f in banner_images:
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

                        # ✅ 新增：同步插入到 banner 表，设置 status=1 和自动排序
                        cur.execute("""
                            INSERT INTO banner (product_id, image_url, sort_order, status)
                            VALUES (%s, %s, %s, 1)
                        """, (id, url, len(banner_urls)))

                    # ✅ 修改：更新 products.main_image 为追加后的完整列表
                    if banner_urls:
                        cur.execute("UPDATE products SET main_image = %s WHERE id = %s",
                                    (json.dumps(banner_urls, ensure_ascii=False), id))

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
                    select_fields=["id", "sku_code", "price", "original_price", "stock", "specifications"]
                )
                cur.execute(select_sql, (id,))
                skus = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']),
                         "original_price": float(s['original_price']) if s['original_price'] else None,
                         "stock": s['stock'], "specifications": s['specifications']} for s in skus]

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
            # ✅ 修改：只统计已支付或已完成的订单
            cur.execute("""
                SELECT SUM(oi.quantity) AS qty, SUM(oi.total_price) AS sales 
                FROM order_items oi
                INNER JOIN orders o ON oi.order_id = o.id
                WHERE oi.product_id = %s 
                AND o.status IN ('pending_ship', 'pending_recv', 'completed')
            """, (id,))

            row = cur.fetchone()
            if not row or not row.get('qty'):
                raise HTTPException(status_code=404, detail="暂无销售数据")

            return {
                "status": "success",
                "data": {
                    "total_quantity": int(row['qty']),
                    "total_sales": float(row['sales'])
                }
            }


# ✅ 新增：删除图片接口
@router.delete("/products/{id}/images", summary="🗑️ 删除商品图片")
def delete_images(
        id: int,
        image_urls: List[str] = Query(..., description="要删除的图片URL列表"),
        image_type: str = Query(..., pattern="^(banner|detail)$",
                                description="图片类型: banner(轮播图) 或 detail(详情图)")
):
    """
    删除指定商品的图片
    - image_type: banner 删除轮播图，detail 删除详情图
    - image_urls: 要删除的图片URL列表
    """
    from pathlib import Path

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

                # 获取当前图片列表
                if image_type == "banner":
                    raw_images = product.get('main_image')
                    banner_table = True  # 需要同步删除 banner 表
                else:  # detail
                    raw_images = product.get('detail_images')
                    banner_table = False

                # 解析图片列表
                current_images = []
                try:
                    if raw_images:
                        if isinstance(raw_images, str) and raw_images.strip().startswith('['):
                            current_images = json.loads(raw_images)
                        elif isinstance(raw_images, list):
                            current_images = raw_images
                except:
                    current_images = []

                if not current_images:
                    return {"status": "success", "message": "图片列表为空，无需删除"}

                # 检查要删除的图片是否存在
                images_to_delete = []
                for url in image_urls:
                    if url in current_images:
                        images_to_delete.append(url)
                    else:
                        raise HTTPException(status_code=400, detail=f"图片不存在: {url}")

                if not images_to_delete:
                    raise HTTPException(status_code=400, detail="没有有效的图片需要删除")

                # 从列表中移除图片
                updated_images = [url for url in current_images if url not in images_to_delete]

                # 更新数据库
                if image_type == "banner":
                    cur.execute("UPDATE products SET main_image = %s WHERE id = %s",
                                (json.dumps(updated_images, ensure_ascii=False), id))

                    # 同步删除 banner 表中的记录
                    for url in images_to_delete:
                        cur.execute("DELETE FROM banner WHERE product_id = %s AND image_url = %s", (id, url))
                else:
                    cur.execute("UPDATE products SET detail_images = %s WHERE id = %s",
                                (json.dumps(updated_images, ensure_ascii=False), id))

                # ✅ 修复：物理删除文件（移除/pic/前缀）
                category = product['category']
                for url in images_to_delete:
                    try:
                        # 移除 /pic/ 前缀，构建正确路径
                        relative_path = url.lstrip('/').replace('pic/', '', 1)  # 只替换第一个 pic/
                        file_path = Path(str(BASE_PIC_DIR)) / relative_path

                        if file_path.exists():
                            file_path.unlink()
                            print(f"✅ 已删除文件: {file_path}")
                        else:
                            print(f"⚠️ 文件不存在: {file_path}")
                    except Exception as e:
                        # 文件删除失败不影响主流程
                        print(f"⚠️ 删除文件失败 {url}: {e}")

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
                    select_fields=["id", "sku_code", "price", "original_price", "stock", "specifications"]
                )
                cur.execute(select_sql, (id,))
                skus = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']),
                         "original_price": float(s['original_price']) if s['original_price'] else None,
                         "stock": s['stock'], "specifications": s['specifications']} for s in skus]

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

                return {
                    "status": "success",
                    "message": f"已删除 {len(images_to_delete)} 张{image_type}图",
                    "data": build_product_dict(updated_product, skus, attributes)
                }
            except HTTPException:
                raise
            except Exception as e:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"删除图片失败: {str(e)}")


# ✅ 新增：更新图片接口（追加式，不覆盖原有图片）
@router.put("/products/{id}/images", summary="🔄 更新商品图片")
def update_images(
        id: int,
        image_type: str = Query(..., pattern="^(banner|detail)$", description="图片类型: banner=轮播图, detail=详情图"),
        files: List[UploadFile] = File(..., description="图片文件列表，最多10张"),
):
    """
    更新商品图片（追加式）
    - 通过 image_type 参数明确指定上传的是轮播图还是详情图
    - 上传的图片会追加到现有的对应图片列表
    - 未选择的图片类型保持原样不变
    """
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

                # 验证文件数量
                if len(files) > 10:
                    raise HTTPException(status_code=400, detail=f"{image_type}图最多10张")

                # 根据类型分别处理
                if image_type == "detail":
                    # ✅ 处理详情图（追加模式）
                    raw_detail = product.get('detail_images')
                    try:
                        if raw_detail:
                            if isinstance(raw_detail, str):
                                detail_urls = json.loads(raw_detail)
                            elif isinstance(raw_detail, list):
                                detail_urls = raw_detail
                            else:
                                detail_urls = []
                        else:
                            detail_urls = []
                    except:
                        detail_urls = []

                    # 处理每个文件
                    for f in files:
                        # 验证文件类型
                        ext = Path(f.filename).suffix.lower()
                        if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                            raise HTTPException(status_code=400, detail="仅支持 JPG/PNG/WEBP")
                        if f.size > 3 * 1024 * 1024:
                            raise HTTPException(status_code=400, detail="详情图单张大小不能超过 3MB")

                        # 保存文件
                        file_name = f"detail_{uuid.uuid4().hex}{ext}"
                        file_path = goods_path / file_name
                        with Image.open(f.file) as im:
                            im = im.convert("RGB")
                            im.thumbnail((750, 2000), Image.LANCZOS)
                            im.save(file_path, "JPEG", quality=80, optimize=True)
                        detail_urls.append(f"/pic/{category}/{id}/{file_name}")

                    # 更新详情图到数据库
                    cur.execute("UPDATE products SET detail_images = %s WHERE id = %s",
                                (json.dumps(detail_urls, ensure_ascii=False), id))

                elif image_type == "banner":
                    # ✅ 处理轮播图（追加模式）
                    raw_main = product.get('main_image')
                    try:
                        if raw_main:
                            if isinstance(raw_main, str) and raw_main.strip().startswith('['):
                                banner_urls = json.loads(raw_main)
                            elif isinstance(raw_main, list):
                                banner_urls = raw_main
                            else:
                                banner_urls = []
                        else:
                            banner_urls = []
                    except:
                        banner_urls = []

                    # 处理每个文件
                    for f in files:
                        # 验证文件类型
                        ext = Path(f.filename).suffix.lower()
                        if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                            raise HTTPException(status_code=400, detail="仅支持 JPG/PNG/WEBP")
                        if f.size > 5 * 1024 * 1024:
                            raise HTTPException(status_code=400, detail="轮播图单张大小不能超过 5MB")

                        # 保存文件
                        file_name = f"banner_{uuid.uuid4().hex}{ext}"
                        file_path = goods_path / file_name
                        with Image.open(f.file) as im:
                            im = im.convert("RGB")
                            im.thumbnail((1200, 1200), Image.LANCZOS)
                            im.save(file_path, "JPEG", quality=85, optimize=True)
                        url = f"/pic/{category}/{id}/{file_name}"
                        banner_urls.append(url)

                        # 追加插入 banner 表记录
                        cur.execute("""
                            INSERT INTO banner (product_id, image_url, sort_order, status)
                            VALUES (%s, %s, %s, 1)
                        """, (id, url, len(banner_urls)))

                    # 更新轮播图到数据库
                    cur.execute("UPDATE products SET main_image = %s WHERE id = %s",
                                (json.dumps(banner_urls, ensure_ascii=False), id))

                conn.commit()

                # 查询最终的商品数据
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
                    select_fields=["id", "sku_code", "price", "original_price", "stock", "specifications"]
                )
                cur.execute(select_sql, (id,))
                skus_result = cur.fetchall()
                skus = [{"id": s['id'], "sku_code": s['sku_code'], "price": float(s['price']),
                         "original_price": float(s['original_price']) if s['original_price'] else None,
                         "stock": s['stock'], "specifications": s['specifications']} for s in skus_result]

                # 获取 attributes
                select_sql = build_dynamic_select(
                    cur,
                    "product_attributes",
                    where_clause="product_id = %s",
                    select_fields=["name", "value"]
                )
                cur.execute(select_sql, (id,))
                attributes_result = cur.fetchall()
                attributes = [{"name": a['name'], "value": a['value']} for a in attributes_result]

                return {
                    "status": "success",
                    "message": f"已上传 {len(files)} 张{image_type}图",
                    "data": build_product_dict(updated_product, skus, attributes)
                }
            except HTTPException:
                raise
            except Exception as e:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"更新图片失败: {str(e)}")