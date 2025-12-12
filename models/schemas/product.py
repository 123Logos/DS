# models/schemas/product.py - 商品系统 Pydantic 模型
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any  # ✅ 新增：导入 Dict, Any
from decimal import Decimal
from datetime import datetime


class ProductStatus:
    """商品状态枚举"""
    DRAFT = 0
    ON_SALE = 1
    OFF_SALE = 2
    OUT_OF_STOCK = 3


class ProductSkuModel(BaseModel):
    """商品SKU模型"""
    id: Optional[int] = None
    product_id: Optional[int] = None
    sku_code: str
    price: Decimal = Field(default=Decimal("0.00"), ge=0)  # 商品现价
    # ✅ 新增字段：商品原价
    original_price: Optional[Decimal] = Field(None, ge=0)
    stock: int = Field(default=0, ge=0)
    # ✅ 新增字段：商品规格（JSON格式）
    specifications: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ProductAttributeModel(BaseModel):
    """商品属性模型"""
    id: Optional[int] = None
    product_id: Optional[int] = None
    name: str = Field(..., max_length=100)
    value: str = Field(..., max_length=255)

    model_config = ConfigDict(from_attributes=True)


class BannerModel(BaseModel):
    """轮播图模型"""
    id: Optional[int] = None
    product_id: int
    image_url: str = Field(..., max_length=500)
    link_url: Optional[str] = Field(None, max_length=500)
    sort_order: int = Field(default=0, ge=0)
    status: int = Field(default=1, ge=0, le=1)
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class ProductModel(BaseModel):
    """商品模型"""
    id: Optional[int] = None
    name: str = Field(..., max_length=255)
    pinyin: Optional[str] = None
    description: Optional[str] = None
    category: str = Field(..., max_length=100)
    main_image: Optional[str] = Field(None, max_length=500)
    detail_images: Optional[str] = None
    status: int = Field(default=ProductStatus.DRAFT, ge=0, le=3)
    user_id: Optional[int] = None
    is_member_product: bool = Field(default=False)
    buy_rule: Optional[str] = None
    freight: Decimal = Field(default=Decimal("0.00"), ge=0)
    # ✅ 新增字段：积分抵扣上限
    max_points_discount: Optional[Decimal] = Field(None, ge=0)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    skus: Optional[List[ProductSkuModel]] = None
    attributes: Optional[List[ProductAttributeModel]] = None
    banners: Optional[List[BannerModel]] = None

    model_config = ConfigDict(from_attributes=True)


class ProductCreateRequest(BaseModel):
    """创建商品请求模型"""
    name: str = Field(..., max_length=255)
    description: Optional[str] = None
    category: str = Field(..., max_length=100)
    main_image: Optional[str] = Field(None, max_length=500)
    detail_images: Optional[str] = None
    status: int = Field(default=ProductStatus.DRAFT, ge=0, le=3)
    user_id: Optional[int] = None
    is_member_product: bool = Field(default=False)
    buy_rule: Optional[str] = None
    freight: Decimal = Field(default=Decimal("0.00"), ge=0)
    # ✅ 新增字段：积分抵扣上限
    max_points_discount: Optional[Decimal] = Field(None, ge=0)
    skus: Optional[List[ProductSkuModel]] = None
    attributes: Optional[List[ProductAttributeModel]] = None


class ProductUpdateRequest(BaseModel):
    """更新商品请求模型"""
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    category: Optional[str] = Field(None, max_length=100)
    main_image: Optional[str] = Field(None, max_length=500)
    detail_images: Optional[str] = None
    status: Optional[int] = Field(None, ge=0, le=3)
    is_member_product: Optional[bool] = None
    buy_rule: Optional[str] = None
    freight: Optional[Decimal] = Field(None, ge=0)
    # ✅ 新增字段：积分抵扣上限
    max_points_discount: Optional[Decimal] = Field(None, ge=0)
    skus: Optional[List[ProductSkuModel]] = None
    attributes: Optional[List[ProductAttributeModel]] = None


class ProductResponse(BaseModel):
    """商品响应模型"""
    id: int
    name: str
    pinyin: Optional[str] = None
    description: Optional[str] = None
    category: str
    main_image: Optional[str] = None
    detail_images: Optional[str] = None
    status: int
    user_id: Optional[int] = None
    is_member_product: bool
    buy_rule: Optional[str] = None
    freight: Decimal
    # ✅ 新增字段：积分抵扣上限
    max_points_discount: Optional[Decimal] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    skus: Optional[List[ProductSkuModel]] = None
    attributes: Optional[List[ProductAttributeModel]] = None
    banners: Optional[List[BannerModel]] = None

    model_config = ConfigDict(from_attributes=True)


class BannerCreateRequest(BaseModel):
    """创建轮播图请求模型"""
    product_id: int
    image_url: str = Field(..., max_length=500)
    link_url: Optional[str] = Field(None, max_length=500)
    sort_order: int = Field(default=0, ge=0)
    status: int = Field(default=1, ge=0, le=1)


class BannerResponse(BaseModel):
    """轮播图响应模型"""
    id: int
    product_id: int
    image_url: str
    link_url: Optional[str] = None
    sort_order: int
    status: int
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)