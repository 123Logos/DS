"""
订单系统模块 - 整合所有订单相关功能
"""
from fastapi import FastAPI
from .cart import router as cart_router
from .order import router as order_router
from .refund import router as refund_router
from .address import router as address_router
from .merchant import router as merchant_router

def register_routes(app: FastAPI):
    """注册订单系统路由到主应用"""
    # 统一使用 "订单系统" 作为主 tag，所有订单相关接口都归类到订单系统
    app.include_router(cart_router, prefix="/cart", tags=["订单系统"])
    app.include_router(order_router, prefix="/order", tags=["订单系统"])
    app.include_router(refund_router, prefix="/refund", tags=["订单系统"])
    app.include_router(address_router, prefix="/address", tags=["订单系统"])
    app.include_router(merchant_router, prefix="/merchant", tags=["订单系统"])
