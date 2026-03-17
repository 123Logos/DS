import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from pydantic import BaseModel, Field, field_validator

from core.database import get_conn
from core.config import BASE_PIC_DIR, CATEGORY_CHOICES
from core.table_access import build_dynamic_select, get_table_structure
from pypinyin import lazy_pinyin, Style
from core.auth import get_current_user
from core.logging import get_logger  # ✅ 新增：日志

logger = get_logger(__name__)  # ✅ 新增：模块级 logger


# ProductStatus 枚举定义
class ProductStatus:
    DRAFT = 0
    ON_SALE = 1
    OFF_SALE = 2
    OUT_OF_STOCK = 3


class HomeRecommendItem(BaseModel):
    product_id: int
    is_recommend: bool = Field(..., description="是否首页推荐，true=推荐，false=不推荐")

class HomeRecommendRequest(BaseModel):
    items: List[HomeRecommendItem]


router = APIRouter(tags=["商品管理"], responses={404: {"description": "未找到"}})


def register_routes(app):
    """注册商品管理路由到主应用"""
    from .ext import router as product_ext_router
    app.include_router(router, prefix="/api", tags=["商品管理"])
    app.include_router(product_ext_router, prefix="/api", tags=["商品管理"])


def to_pinyin(text: str) -> str:
    return " ".join(lazy_pinyin(text, style=Style.NORMAL)).upper()


def _validate_placeholder_count(sql_fragment: Optional[str], params: List[Any]):
    """简单校验：确保 SQL 片段中的 `%s` 占位符数量与 params 数量一致。"""
    if not sql_fragment:
        return
    placeholder_count = sql_fragment.count("%s")
    if placeholder_count != len(params):
        raise HTTPException(status_code=400,
                            detail=f"SQL 占位符数量({placeholder_count})与参数数量({len(params)})不匹配")


def _safe_concat_or(conds: List[str]) -> str:
    """安全地将多个条件用 OR 连接。"""
    if not conds:
        return ""
    for c in conds:
        if not isinstance(c, str):
            raise HTTPException(status_code=400, detail="非法的SQL条件类型")
        if ";" in c or "--" in c or "/*" in c or "*/" in c:
            raise HTTPException(status_code=400, detail="检测到不安全的SQL片段")
    return " OR ".join(conds)


# ✅ 新增：处理可选文件上传的依赖函数
def get_optional_files(files: Optional[List[UploadFile]] = File(None)) -> Optional[List[UploadFile]]:
    if files is None:
        return None
    valid_files = [f for f in files if f is not None and hasattr(f, 'filename') and f.filename]
    return valid_files if valid_files else None


# ✅ PRODUCT_COLUMNS 中添加 max_points_discount
PRODUCT_COLUMNS = ["id", "name", "pinyin", "description", "category",
                   "main_image", "detail_images", "status", "user_id",
                   "is_member_product", "buy_rule", "freight",
                   "created_at", "updated_at", "max_points_discount",
                   "is_home_recommend", "reward_rain", "reward_points", "is_virtual",
                   "cash_only"]   # 新增


def build_product_dict(product: Dict[str, Any], skus: List[Dict[str, Any]] = None,
                       attributes: List[Dict[str, Any]] = None) -> Dict[str, Any]:
    """从数据库查询结果构建商品字典（pymysql 版本）"""
    base = {col: product.get(col) for col in PRODUCT_COLUMNS}
    base["skus"] = skus or []
    base["attributes"] = attributes or []
    base["freight"] = 0.00

    if 'merchant_name' in product and product['merchant_name']:
        base['merchant_name'] = product['merchant_name']

    # 处理 JSON 字段
    if base.get("detail_images"):
        if isinstance(base["detail_images"], str):
            try:
                base["detail_images"] = json.loads(base["detail_images"])
            except:
                base["detail_images"] = []
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
    price: float = Field(..., ge=0)
    original_price: Optional[float] = Field(None, ge=0)
    specifications: Optional[Dict[str, Any]] = None
    stock: int = Field(..., ge=0)

    @field_validator("price")
    def force_member_price(cls, v: float, info):
        return v


class SkuUpdate(BaseModel):
    id: Optional[int] = None
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
    max_points_discount: Optional[float] = Field(None, ge=0, description="积分抵扣上限")
    reward_rain: Optional[float] = Field(0.0, ge=0, description="赠送雨点数量")
    reward_points: Optional[float] = Field(0.0, ge=0, description="赠送积分数量")
    is_virtual: Optional[bool] = Field(False, description="是否为虚拟商品，虚拟商品支付后自动完成")
    cash_only: bool = Field(False, description="是否只能用现金支付（禁止积分和优惠券）")
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
    max_points_discount: Optional[float] = Field(None, ge=0, description="积分抵扣上限")
    reward_rain: Optional[float] = Field(None, ge=0, description="赠送雨点数量")
    reward_points: Optional[float] = Field(None, ge=0, description="赠送积分数量")
    is_virtual: Optional[bool] = Field(None, description="是否为虚拟商品，虚拟商品支付后自动完成")
    cash_only: Optional[bool] = Field(None, description="是否只能用现金支付（禁止积分和优惠券）")
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


class ImageDeleteRequest(BaseModel):
    image_urls: List[str]
    image_type: str = Field(..., pattern="^(banner|detail)$")


class ImageUpdateRequest(BaseModel):
    detail_images: Optional[List[str]] = None
    banner_images: Optional[List[str]] = None


# ---------------- 中文路由摘要 + 修复上下文 ----------------

@router.get("/products/search", summary="🔍 商品模糊搜索（SKU精确匹配）")
def search_products(
        keyword: str = Query(..., min_length=1,
                             description="搜索关键词（名称/描述/拼音/分类/商家模糊搜索，SKU编码精确匹配）。多个关键词用空格分隔")
):
    # 原有实现，无需登录
    kw = keyword.strip()
    if not kw:
        return {"status": "success", "data": []}

    words = [w for w in kw.split() if w]
    if not words:
        return {"status": "success", "data": []}

    with get_conn() as conn:
        with conn.cursor() as cur:
            conditions = []
            params = []

            for word in words:
                word_pattern = f"%{word}%"
                word_conditions = []

                word_conditions.append("p.name LIKE %s")
                params.append(word_pattern)
                word_conditions.append("p.description LIKE %s")
                params.append(word_pattern)
                word_conditions.append("p.pinyin LIKE %s")
                params.append(word_pattern)
                word_conditions.append("p.category LIKE %s")
                params.append(word_pattern)

                word_conditions.append("ps.sku_code = %s")
                params.append(word)

                word_conditions.append("(u.name LIKE %s AND u.is_merchant = 1)")
                params.append(word_pattern)

                conditions.append("(" + _safe_concat_or(word_conditions) + ")")

            where_clause = " AND ".join(conditions)
            _validate_placeholder_count(where_clause, params)

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

            result_data = []
            for product in products:
                product_id = product['id']

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
        user_id: Optional[int] = Query(None, description="商家ID筛选"),
        page: int = Query(1, ge=1, description="页码"),
        size: int = Query(10, ge=1, le=100, description="每页条数"),
):
    # 公开查询，无需登录
    with get_conn() as conn:
        with conn.cursor() as cur:
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
            if user_id is not None:
                where_clauses.append("user_id = %s")
                params.append(user_id)

            where_sql = " WHERE " + " AND ".join(where_clauses) if where_clauses else ""

            if where_clauses:
                _validate_placeholder_count(" AND ".join(where_clauses), params)

            count_sql = f"SELECT COUNT(*) as total FROM products{where_sql}"
            cur.execute(count_sql, tuple(params))
            total = cur.fetchone()['total']

            offset = (page - 1) * size
            where_clause_clean = " AND ".join(where_clauses) if where_clauses else None
            select_sql_base = build_dynamic_select(
                cur,
                "products",
                where_clause=where_clause_clean,
                order_by="id DESC"
            )
            select_sql = f"{select_sql_base} LIMIT %s OFFSET %s"
            cur.execute(select_sql, tuple(params + [size, offset]))
            products = cur.fetchall()

            result_data = []
            for product in products:
                product_id = product['id']

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


@router.get("/products/home", summary="🏠 获取首页推荐商品列表")
def get_home_products():
    # 公开接口
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(
                cur,
                "products",
                where_clause="is_home_recommend = 1",
                order_by="id DESC"  # 可按需调整排序规则，例如按创建时间倒序
            )
            cur.execute(select_sql)
            products = cur.fetchall()

            result_data = []
            for product in products:
                product_id = product['id']
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


@router.get("/products/{id}", summary="📦 查询单个商品")
def get_product(id: int):
    # 公开接口
    with get_conn() as conn:
        with conn.cursor() as cur:
            select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
            cur.execute(select_sql, (id,))
            product = cur.fetchone()
            if not product:
                raise HTTPException(status_code=404, detail="商品不存在")

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


# ✅ 新增商品（需要登录且必须是商家或平台）
@router.post("/products", summary="➕ 新增商品")
def add_product(
    payload: ProductCreate,
    current_user: Dict[str, Any] = Depends(get_current_user)  # 新增依赖
):
    # 强制使用当前登录用户的ID，忽略 payload.user_id
    user_id = current_user['id']
    # 校验当前用户是否为商家或平台
    merchant_type = current_user.get('is_merchant', 0)
    if merchant_type not in [1, 2]:
        raise HTTPException(status_code=403, detail="只有商家或平台可以发布商品")

    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 处理会员商品价格: 强制所有SKU价格为1980
                sku_prices = []
                for sku in payload.skus:
                    if payload.is_member_product:
                        sku_prices.append(1980.0)
                    else:
                        sku_prices.append(sku.price)

                pinyin = to_pinyin(payload.name)
                cur.execute("""
                    INSERT INTO products (name, pinyin, description, category, status, user_id, 
                                        is_member_product, buy_rule, freight, max_points_discount,
                                        reward_rain, reward_points, is_virtual, cash_only)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (payload.name, pinyin, payload.description, payload.category, payload.status,
                      user_id, payload.is_member_product, payload.buy_rule, 0.0,
                      payload.max_points_discount, payload.reward_rain, payload.reward_points,
                      payload.is_virtual, payload.cash_only))
                product_id = cur.lastrowid

                # 插入 SKUs
                for sku, price in zip(payload.skus, sku_prices):
                    cur.execute("""
                        INSERT INTO product_skus (product_id, sku_code, price, original_price, stock, specifications)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        product_id,
                        sku.sku_code,
                        price,
                        sku.original_price,
                        sku.stock,
                        json.dumps(sku.specifications, ensure_ascii=False) if sku.specifications else None
                    ))

                # 插入 attributes
                if payload.attributes:
                    for attr in payload.attributes:
                        if isinstance(attr, dict) and "name" in attr and "value" in attr:
                            a_name = attr["name"]
                            a_value = attr["value"]
                        elif isinstance(attr, dict) and len(attr) >= 1:
                            k, v = next(iter(attr.items()))
                            a_name = k
                            a_value = v
                        else:
                            continue  # 跳过无效属性
                        cur.execute("""
                            INSERT INTO product_attributes (product_id, name, value)
                            VALUES (%s, %s, %s)
                        """, (product_id, a_name, a_value))

                conn.commit()

                # 查询创建的商品
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (product_id,))
                product = cur.fetchone()

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


@router.put("/products/home-recommend", summary="⚙️ 批量设置商品首页推荐")
def set_home_recommend(
    payload: HomeRecommendRequest,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    # 原接口已具备权限校验
    if current_user.get('is_merchant') != 2:
        raise HTTPException(
            status_code=403,
            detail="只有平台管理员可以操作此接口"
        )

    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                for item in payload.items:
                    cur.execute(
                        "UPDATE products SET is_home_recommend = %s WHERE id = %s",
                        (1 if item.is_recommend else 0, item.product_id)
                    )
                conn.commit()
                return {"status": "success", "message": f"已更新 {len(payload.items)} 个商品的首页推荐权重"}
            except Exception as e:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"操作失败: {str(e)}")


# ✅ 更新商品（需要登录且必须是商品拥有者或平台管理员）
@router.put("/products/{id}", summary="✏️ 更新商品")
def update_product(
    id: int,
    payload: ProductUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user)  # 新增依赖
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 检查商品是否存在并获取其 user_id
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (id,))
                product = cur.fetchone()
                if not product:
                    raise HTTPException(status_code=404, detail="商品不存在")

                # 权限校验：必须是商品拥有者或平台管理员
                if product['user_id'] != current_user['id'] and current_user.get('is_merchant') != 2:
                    raise HTTPException(status_code=403, detail="您没有权限修改此商品")

                # 如果试图更改 user_id，只有平台管理员允许
                if payload.user_id is not None and payload.user_id != product['user_id']:
                    if current_user.get('is_merchant') != 2:
                        raise HTTPException(status_code=403, detail="只有平台管理员可以转移商品所有权")

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

                # 特别注意 cash_only 可能为 False，所以需要判断是否为 None
                if 'cash_only' in update_data:
                    # 如果已经在循环中处理了，则不用重复；但上述循环会处理所有非 None 字段
                    pass  # 上面循环已处理

                if update_fields:
                    from core.table_access import build_select_list
                    update_params.append(id)
                    cur.execute(f"""
                        UPDATE products 
                        SET {build_select_list(update_fields)}, updated_at = NOW()
                        WHERE id = %s
                    """, tuple(update_params))

                # 智能SKU管理系统（原逻辑不变）
                if payload.skus is not None:
                    provided_sku_ids = []
                    for sku_update in payload.skus:
                        if not sku_update.id:
                            if not sku_update.sku_code or sku_update.price is None or sku_update.stock is None:
                                raise HTTPException(
                                    status_code=400,
                                    detail="新增SKU必须提供sku_code、price和stock字段"
                                )
                            cur.execute("""
                                INSERT INTO product_skus 
                                (product_id, sku_code, price, original_price, stock, specifications)
                                VALUES (%s, %s, %s, %s, %s, %s)
                            """, (
                                id,
                                sku_update.sku_code,
                                sku_update.price,
                                sku_update.original_price,
                                sku_update.stock,
                                json.dumps(sku_update.specifications, ensure_ascii=False)
                                if sku_update.specifications else None
                            ))
                            new_sku_id = cur.lastrowid
                            provided_sku_ids.append(new_sku_id)
                            logger.info(f"✅ 新增SKU: {sku_update.sku_code} (ID: {new_sku_id})")  # ✅ 替换 print
                            continue

                        provided_sku_ids.append(sku_update.id)
                        sku_fields = []
                        sku_params = []

                        if sku_update.sku_code is not None:
                            sku_fields.append("sku_code = %s")
                            sku_params.append(sku_update.sku_code)
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
                            cur.execute("SELECT 1 FROM product_skus WHERE id = %s AND product_id = %s",
                                        (sku_update.id, id))
                            if not cur.fetchone():
                                raise HTTPException(status_code=400, detail=f"SKU ID {sku_update.id} 不属于商品 {id}")

                            sku_params.extend([sku_update.id, id])
                            from core.table_access import build_select_list
                            cur.execute(f"""
                                UPDATE product_skus 
                                SET {build_select_list(sku_fields)}, updated_at = NOW()
                                WHERE id = %s AND product_id = %s
                            """, tuple(sku_params))
                            logger.info(f"✅ 更新SKU ID {sku_update.id}")  # ✅ 替换 print

                    if provided_sku_ids:
                        format_ids = ','.join(['%s'] * len(provided_sku_ids))
                        delete_params = [id] + provided_sku_ids
                        cur.execute(f"""
                            DELETE FROM product_skus 
                            WHERE product_id = %s AND id NOT IN ({format_ids})
                        """, tuple(delete_params))

                        deleted_count = cur.rowcount
                        if deleted_count > 0:
                            logger.info(f"✅ 删除 {deleted_count} 个未提及的SKU")  # ✅ 替换 print
                    else:
                        logger.warning("⚠️ 未提供任何SKU ID，跳过删除逻辑")  # ✅ 替换 print

                elif new_is_member is True:
                    cur.execute("""
                        UPDATE product_skus 
                        SET price = 1980.00, updated_at = NOW()
                        WHERE product_id = %s
                    """, (id,))
                    logger.info("✅ 会员商品：强制所有SKU价格为1980")  # ✅ 替换 print

                # 更新 attributes
                if payload.attributes is not None:
                    cur.execute("DELETE FROM product_attributes WHERE product_id = %s", (id,))
                    for attr in payload.attributes:
                        if isinstance(attr, dict) and "name" in attr and "value" in attr:
                            a_name = attr["name"]
                            a_value = attr["value"]
                        elif isinstance(attr, dict) and len(attr) >= 1:
                            k, v = next(iter(attr.items()))
                            a_name = k
                            a_value = v
                        else:
                            continue
                        cur.execute("""
                            INSERT INTO product_attributes (product_id, name, value)
                            VALUES (%s, %s, %s)
                        """, (id, a_name, a_value))

                conn.commit()

                # 查询更新后的商品
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (id,))
                updated_product = cur.fetchone()

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


# ✅ 删除商品（需要登录且必须是商品拥有者或平台管理员，同时检查未完成订单）
@router.delete("/products/{id}", summary="🗑️ 删除商品")
def delete_product(
    id: int,
    current_user: Dict[str, Any] = Depends(get_current_user)  # 新增依赖
):
    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 检查商品是否存在
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (id,))
                product = cur.fetchone()
                if not product:
                    raise HTTPException(status_code=404, detail="商品不存在")

                # 权限校验
                if product['user_id'] != current_user['id'] and current_user.get('is_merchant') != 2:
                    raise HTTPException(status_code=403, detail="您没有权限删除此商品")

                # 检查是否有未完成的订单关联此商品（防止数据不一致）
                cur.execute("""
                    SELECT 1 FROM order_items oi
                    JOIN orders o ON oi.order_id = o.id
                    WHERE oi.product_id = %s AND o.status NOT IN ('completed', 'refunded')
                    LIMIT 1
                """, (id,))
                if cur.fetchone():
                    raise HTTPException(status_code=400, detail="该商品存在未完成的订单，无法删除")

                # 获取图片列表用于后续删除物理文件
                raw_main = product.get('main_image', '[]')
                raw_detail = product.get('detail_images', '[]')

                image_urls_to_delete = []
                try:
                    if isinstance(raw_main, str) and raw_main.strip().startswith('['):
                        image_urls_to_delete.extend(json.loads(raw_main))
                    elif isinstance(raw_main, list):
                        image_urls_to_delete.extend(raw_main)
                except:
                    pass

                try:
                    if isinstance(raw_detail, str) and raw_detail.strip().startswith('['):
                        image_urls_to_delete.extend(json.loads(raw_detail))
                    elif isinstance(raw_detail, list):
                        image_urls_to_delete.extend(raw_detail)
                except:
                    pass

                cur.execute("DELETE FROM products WHERE id = %s", (id,))
                if cur.rowcount == 0:
                    raise HTTPException(status_code=404, detail="商品删除失败或已被删除")

                conn.commit()

                # 异步删除物理文件
                if image_urls_to_delete:
                    from pathlib import Path
                    for url in image_urls_to_delete:
                        try:
                            relative_path = url.lstrip('/').replace('pic/', '', 1)
                            file_path = Path(str(BASE_PIC_DIR)) / relative_path
                            if file_path.exists():
                                file_path.unlink()
                                logger.info(f"✅ 已删除商品图片文件: {file_path}")  # ✅ 替换 print
                            else:
                                logger.warning(f"⚠️ 文件不存在: {file_path}")  # ✅ 新增（原无，但可统一处理）
                        except Exception as e:
                            logger.warning(f"⚠️ 删除图片文件失败 {url}: {e}")  # ✅ 替换 print

                return {
                    "status": "success",
                    "message": f"商品 {id} 已成功删除",
                    "data": {"product_id": id}
                }
            except HTTPException:
                raise
            except Exception as e:
                conn.rollback()
                raise HTTPException(status_code=400, detail=f"删除商品失败: {str(e)}")


# ✅ 上传商品图片（需要登录且必须是商品拥有者或平台管理员）
@router.post("/products/{id}/images", summary="📸 上传商品图片")
def upload_images(
        id: int,
        current_user: Dict[str, Any] = Depends(get_current_user),  # 新增依赖
        detail_images: List[UploadFile] = File([], description="详情图，最多10张，单张<10MB，仅JPG/PNG/WEBP"),
        banner_images: List[UploadFile] = File([], description="轮播图，最多10张，单张<10MB，仅JPG/PNG/WEBP"),
):
    from PIL import Image
    import uuid

    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 查询商品
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (id,))
                product = cur.fetchone()
                if not product:
                    raise HTTPException(status_code=404, detail="商品不存在")

                # 权限校验
                if product['user_id'] != current_user['id'] and current_user.get('is_merchant') != 2:
                    raise HTTPException(status_code=403, detail="您没有权限操作此商品的图片")

                # 初始化图片列表
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
                        if f.size > 10 * 1024 * 1024:
                            raise HTTPException(status_code=400, detail="详情图单张大小不能超过 10MB")
                        file_name = f"detail_{uuid.uuid4().hex}{ext}"
                        file_path = goods_path / file_name
                        with Image.open(f.file) as im:
                            im = im.convert("RGB")
                            im.thumbnail((750, 2000), Image.LANCZOS)
                            im.save(file_path, "JPEG", quality=80, optimize=True)
                        detail_urls.append(f"/pic/{category}/{id}/{file_name}")

                    cur.execute("UPDATE products SET detail_images = %s WHERE id = %s",
                                (json.dumps(detail_urls, ensure_ascii=False), id))

                if banner_images:
                    if len(banner_images) > 10:
                        raise HTTPException(status_code=400, detail="轮播图最多10张")

                    for f in banner_images:
                        ext = Path(f.filename).suffix.lower()
                        if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                            raise HTTPException(status_code=400, detail="仅支持 JPG/PNG/WEBP")
                        if f.size > 10 * 1024 * 1024:
                            raise HTTPException(status_code=400, detail="轮播图单张大小不能超过 10MB")
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
                            VALUES (%s, %s, %s, 1)
                        """, (id, url, len(banner_urls)))

                    if banner_urls:
                        cur.execute("UPDATE products SET main_image = %s WHERE id = %s",
                                    (json.dumps(banner_urls, ensure_ascii=False), id))

                conn.commit()

                # 查询更新后的商品
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (id,))
                updated_product = cur.fetchone()

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


# 以下公开接口保持不变（轮播图列表、销售数据、用户商品列表等）
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
            cur.execute("""
                SELECT 
                    SUM(oi.quantity) AS qty, 
                    SUM(oi.total_price) AS sales 
                FROM order_items oi
                INNER JOIN orders o ON oi.order_id = o.id
                WHERE oi.product_id = %s 
                AND o.status IN ('pending_ship', 'pending_recv', 'completed')
                AND COALESCE(o.refund_status, '') != 'refund_success'
            """, (id,))

            row = cur.fetchone()
            if not row or not row.get('qty'):
                qty = int(row['qty']) if row and row.get('qty') else 0
                sales = float(row['sales']) if row and row.get('sales') else 0.0

                return {
                    "status": "success",
                    "data": {
                        "total_quantity": qty,
                        "total_sales": sales
                    }
                }

            return {
                "status": "success",
                "data": {
                    "total_quantity": int(row['qty']),
                    "total_sales": float(row['sales'])
                }
            }


# ✅ 删除图片（需要登录且必须是商品拥有者或平台管理员）
@router.delete("/products/{id}/images", summary="🗑️ 删除商品图片")
def delete_images(
        id: int,
        image_urls: List[str] = Query(..., description="要删除的图片URL列表"),
        image_type: str = Query(..., pattern="^(banner|detail)$",
                                description="图片类型: banner(轮播图) 或 detail(详情图)"),
        current_user: Dict[str, Any] = Depends(get_current_user)  # 新增依赖
):
    from pathlib import Path

    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 查询商品
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (id,))
                product = cur.fetchone()
                if not product:
                    raise HTTPException(status_code=404, detail="商品不存在")

                # 权限校验
                if product['user_id'] != current_user['id'] and current_user.get('is_merchant') != 2:
                    raise HTTPException(status_code=403, detail="您没有权限操作此商品的图片")

                # 获取当前图片列表
                if image_type == "banner":
                    raw_images = product.get('main_image')
                    banner_table = True
                else:
                    raw_images = product.get('detail_images')
                    banner_table = False

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

                images_to_delete = []
                for url in image_urls:
                    if url in current_images:
                        images_to_delete.append(url)
                    else:
                        raise HTTPException(status_code=400, detail=f"图片不存在: {url}")

                if not images_to_delete:
                    raise HTTPException(status_code=400, detail="没有有效的图片需要删除")

                updated_images = [url for url in current_images if url not in images_to_delete]

                if image_type == "banner":
                    cur.execute("UPDATE products SET main_image = %s WHERE id = %s",
                                (json.dumps(updated_images, ensure_ascii=False), id))

                    for url in images_to_delete:
                        cur.execute("DELETE FROM banner WHERE product_id = %s AND image_url = %s", (id, url))
                else:
                    cur.execute("UPDATE products SET detail_images = %s WHERE id = %s",
                                (json.dumps(updated_images, ensure_ascii=False), id))

                category = product['category']
                for url in images_to_delete:
                    try:
                        relative_path = url.lstrip('/').replace('pic/', '', 1)
                        file_path = Path(str(BASE_PIC_DIR)) / relative_path
                        if file_path.exists():
                            file_path.unlink()
                            logger.info(f"✅ 已删除文件: {file_path}")  # ✅ 替换 print
                        else:
                            logger.warning(f"⚠️ 文件不存在: {file_path}")  # ✅ 替换 print
                    except Exception as e:
                        logger.warning(f"⚠️ 删除文件失败 {url}: {e}")  # ✅ 替换 print

                conn.commit()

                # 查询更新后的商品
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (id,))
                updated_product = cur.fetchone()

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


# ✅ 更新图片（追加式，需要登录且必须是商品拥有者或平台管理员）
@router.put("/products/{id}/images", summary="🔄 更新商品图片")
def update_images(
        id: int,
        image_type: str = Query(..., pattern="^(banner|detail)$", description="图片类型: banner=轮播图, detail=详情图"),
        files: List[UploadFile] = File(..., description="图片文件列表，最多10张，单张<10MB"),
        current_user: Dict[str, Any] = Depends(get_current_user)  # 新增依赖
):
    from PIL import Image
    import uuid

    with get_conn() as conn:
        with conn.cursor() as cur:
            try:
                # 查询商品
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (id,))
                product = cur.fetchone()
                if not product:
                    raise HTTPException(status_code=404, detail="商品不存在")

                # 权限校验
                if product['user_id'] != current_user['id'] and current_user.get('is_merchant') != 2:
                    raise HTTPException(status_code=403, detail="您没有权限操作此商品的图片")

                category = product['category']
                cat_path = BASE_PIC_DIR / category
                goods_path = cat_path / str(id)
                goods_path.mkdir(parents=True, exist_ok=True)

                if len(files) > 10:
                    raise HTTPException(status_code=400, detail=f"{image_type}图最多10张")

                if image_type == "detail":
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

                    for f in files:
                        ext = Path(f.filename).suffix.lower()
                        if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                            raise HTTPException(status_code=400, detail="仅支持 JPG/PNG/WEBP")
                        if f.size > 10 * 1024 * 1024:
                            raise HTTPException(status_code=400, detail="详情图单张大小不能超过 10MB")

                        file_name = f"detail_{uuid.uuid4().hex}{ext}"
                        file_path = goods_path / file_name
                        with Image.open(f.file) as im:
                            im = im.convert("RGB")
                            im.thumbnail((750, 2000), Image.LANCZOS)
                            im.save(file_path, "JPEG", quality=80, optimize=True)
                        detail_urls.append(f"/pic/{category}/{id}/{file_name}")

                    cur.execute("UPDATE products SET detail_images = %s WHERE id = %s",
                                (json.dumps(detail_urls, ensure_ascii=False), id))

                elif image_type == "banner":
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

                    for f in files:
                        ext = Path(f.filename).suffix.lower()
                        if ext not in {".jpg", ".jpeg", ".png", ".webp"}:
                            raise HTTPException(status_code=400, detail="仅支持 JPG/PNG/WEBP")
                        if f.size > 10 * 1024 * 1024:
                            raise HTTPException(status_code=400, detail="轮播图单张大小不能超过 10MB")

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
                            VALUES (%s, %s, %s, 1)
                        """, (id, url, len(banner_urls)))

                    cur.execute("UPDATE products SET main_image = %s WHERE id = %s",
                                (json.dumps(banner_urls, ensure_ascii=False), id))

                conn.commit()

                # 查询更新后的商品
                select_sql = build_dynamic_select(cur, "products", where_clause="id = %s")
                cur.execute(select_sql, (id,))
                updated_product = cur.fetchone()

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


# ============================================================
# 根据用户ID查询商品列表（仅商家/平台可查询）—— 本接口已自带权限校验
# ============================================================
@router.get("/users/{user_id}/products", summary="👤 查询用户的所有商品")
def get_user_products(
        user_id: int,
        status: Optional[int] = Query(None, description="商品状态筛选"),
        page: int = Query(1, ge=1, description="页码"),
        size: int = Query(10, ge=1, le=100, description="每页条数"),
):
    # 原有实现，已包含对目标用户是否为商家的校验，无需登录
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, name, is_merchant FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="用户不存在")

            merchant_type = user.get('is_merchant', 0)
            if merchant_type not in [1, 2]:
                raise HTTPException(
                    status_code=403,
                    detail="该用户不是商家或平台，无法查询商品"
                )

            where_clauses = ["p.user_id = %s"]
            params = [user_id]

            if status is not None:
                where_clauses.append("p.status = %s")
                params.append(status)

            where_sql = " AND ".join(where_clauses)

            cur.execute(f"""
                SELECT COUNT(*) as total 
                FROM products p
                WHERE {where_sql}
            """, tuple(params))
            total = cur.fetchone()['total']

            offset = (page - 1) * size
            cur.execute(f"""
                SELECT p.*, u.name as merchant_name
                FROM products p
                LEFT JOIN users u ON u.id = p.user_id
                WHERE {where_sql}
                ORDER BY p.id DESC
                LIMIT %s OFFSET %s
            """, tuple(params + [size, offset]))
            products = cur.fetchall()

            result_data = []
            for product in products:
                product_id = product['id']

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

            return {
                "status": "success",
                "user_id": user_id,
                "user_name": user.get('name'),
                "user_type": "商家" if merchant_type == 1 else "平台",
                "total": total,
                "page": page,
                "size": size,
                "data": result_data
            }