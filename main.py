"""
统一的应用入口 - 集中创建 FastAPI 实例和配置
"""
import sys
from pathlib import Path
import uvicorn
import pymysql
from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html, get_swagger_ui_oauth2_redirect_html, get_redoc_html
from core.json_response import DecimalJSONResponse, register_exception_handlers
from fastapi.staticfiles import StaticFiles
from core.middleware import setup_cors, setup_static_files
from core.config import get_db_config, PIC_PATH, AVATAR_UPLOAD_DIR,UVICORN_PORT
from core.logging import setup_logging
from database_setup import initialize_database
from api.wechat_pay.routes import register_wechat_pay_routes
from core.logging import get_logger

logger = get_logger(__name__)

# 配置日志（如果需要同时输出到控制台，可以设置 log_to_console=True）
setup_logging(log_to_file=True, log_to_console=True)

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent))

# 导入路由注册函数（使用新的目录结构）
from api.finance.routes import register_finance_routes
from api.user.routes import register_routes as register_user_routes
from api.order import register_routes as register_order_routes
from api.product.routes import register_routes as register_product_routes
from api.system.routes import register_routes as register_system_routes
from api.wechat_applyment.routes import register_wechat_applyment_routes
from api.store_setup.routes import register_store_routes
# 删除或注释掉旧的导入：from api.user.bankcard_routes import register_bankcard_routes
# 新增导入：
from api.bankcard.routes import register_bankcard_routes
from api.offline.routes import register_offline_routes

def ensure_database():
    """确保数据库存在"""
    try:
        cfg = get_db_config()
        pymysql.connect(
            host=cfg['host'],
            port=cfg['port'],
            user=cfg['user'],
            password=cfg['password'],
            database=cfg['database'],
            charset=cfg['charset'],
            cursorclass=pymysql.cursors.DictCursor
        ).close()
    except pymysql.err.OperationalError as e:
        if e.args[0] == 1049:
            print("📦 数据库不存在，正在自动创建并初始化 …")
            initialize_database()
            print("✅ 自动初始化完成！")
        else:
            raise


# 创建统一的 FastAPI 应用实例
app = FastAPI(
    title="综合管理系统API",
    description="财务管理系统 + 用户中心 + 订单系统 + 商品管理",
    version="1.0.0",
    docs_url="/docs",  # 自定义 docs 路由以支持搜索过滤
    redoc_url="/redoc",  # ReDoc 文档地址
    openapi_url="/openapi.json",  # OpenAPI Schema 地址
    default_response_class=DecimalJSONResponse
)
# 注册全局异常处理器（放在 core/json_response.py 中实现）
register_exception_handlers(app)


# 在每次应用启动时初始化数据库表结构（幂等）
@app.on_event("startup")
def on_startup():
    logger.info("应用启动：检查并初始化数据库表结构与后台任务")
    try:
        initialize_database()
    except Exception as e:
        logger.error(f"初始化数据库失败: {e}")

# ... 原有代码保持不变 ...

tags_metadata = [
    {
        "name": "财务系统",
        "description": "财务管理系统相关接口，包括用户管理、订单结算、退款、补贴、提现、奖励、报表等功能。",
    },
    {
        "name": "用户中心",
        "description": "用户中心相关接口，包括用户认证、资料管理、地址管理、积分管理、团队奖励、董事功能等。",
    },
    {
        "name": "订单系统",
        "description": "订单系统相关接口，包括购物车、订单管理、退款、商家后台等功能。",
    },
    {
        "name": "商品管理",
        "description": "商品管理系统相关接口，包括商品搜索、商品列表、商品详情、商品创建、商品更新、图片上传、轮播图、销售数据等功能。",
    },
    {
        "name": "系统配置",
        "description": "系统配置相关接口，包括系统标语、轮播图标语等配置管理。",
    },
    {
        "name": "店铺设置",
        "description": "店铺设置相关接口，包括店铺信息创建、更新、查询、LOGO上传、设置状态查询等功能。",
    },
    {
        "name": "微信进件",
        "description": "微信支付进件相关接口，包括实名认证、进件申请、材料上传、状态查询等功能。",
    },
    # ==================== ✅ 新增：微信支付标签 ====================
    {
        "name": "微信支付",
        "description": "微信支付相关接口，包括支付回调、订单查询等功能。",
    },
    # ============================================================
    {
        "name": "银行卡管理",
        "description": "银行卡绑定、解绑、改绑、状态查询等独立功能模块。",
    },
    {
        "name": "线下收银台付款模块",
        "description": "支付单创建,收款码生成,用户支付，后续管理等功能。",
    },
]

# ... 后续代码保持不变 ...

# 更新 OpenAPI Schema 的 tags 元数据
app.openapi_tags = tags_metadata

# 按优先级先挂载 avatars（用户头像），再挂载 /pic 到商品图片目录
app.mount("/pic/avatars", StaticFiles(directory=str(AVATAR_UPLOAD_DIR)), name="avatars")
app.mount("/pic", StaticFiles(directory=str(PIC_PATH)), name="pic")
# 添加 CORS 中间件和静态文件（统一配置）pic_path
setup_cors(app)
setup_static_files(app)

# 注册所有模块的路由（必须在设置 custom_openapi 之前注册）
register_finance_routes(app)
register_user_routes(app)
register_order_routes(app)
register_product_routes(app)
register_system_routes(app)
register_wechat_applyment_routes(app)  # 添加这一行
register_wechat_pay_routes(app)
register_store_routes(app)
register_bankcard_routes(app) # 修改：注册新的银行卡路由
register_offline_routes(app)

# 自定义 OpenAPI Schema 生成函数，确保只显示定义的4个标签
# 注意：必须在路由注册之后设置，否则 schema 中不会包含路由
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi
    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=tags_metadata,
    )
    # 过滤掉未定义的标签，只保留 tags_metadata 中定义的标签
    defined_tag_names = {tag["name"] for tag in tags_metadata}
    if "tags" in openapi_schema:
        openapi_schema["tags"] = [tag for tag in openapi_schema["tags"] if tag["name"] in defined_tag_names]
    # 确保所有路径的 tags 都在定义的标签列表中
    if "paths" in openapi_schema:
        for path_item in openapi_schema["paths"].values():
            for operation in path_item.values():
                if "tags" in operation and operation["tags"]:
                    # 如果路由使用了未定义的标签，根据内容替换为合适的标签
                    filtered_tags = []
                    for tag in operation["tags"]:
                        if tag in defined_tag_names:
                            filtered_tags.append(tag)
                        elif "订单系统" in tag:
                            filtered_tags.append("订单系统")
                        elif "商品" in tag or "商品管理" in tag or "商品扩展" in tag:
                            filtered_tags.append("商品管理")
                    operation["tags"] = filtered_tags if filtered_tags else ["商品管理"]
    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


# 自定义 Swagger UI 页面，启用 filter 参数以支持输入字母快速搜索 API
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Swagger UI",
        swagger_ui_parameters={"filter": True}
    )


# Swagger UI oauth2 redirect 支持
@app.get(app.swagger_ui_oauth2_redirect_url, include_in_schema=False)
async def swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()


# ReDoc 页面（全文搜索），保留在 /redoc
@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(openapi_url=app.openapi_url, title=f"{app.title} - ReDoc")


if __name__ == "__main__":
    post = UVICORN_PORT
    # 初始化数据库表结构
    print("正在初始化数据库...")
    initialize_database()

    # 确保数据库存在
    ensure_database()

    print("启动综合管理系统 API...")
    print(f"财务管理系统 API 文档: http://127.0.0.1:{post}/docs")
    print(f"用户中心 API 文档: http://127.0.0.1:{post}/docs")
    print(f"订单系统 API 文档: http://127.0.0.1:{post}/docs")
    print(f"商品管理系统 API 文档: http://127.0.0.1:{post}/docs")

    # 使用导入字符串以支持热重载
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=post,
        reload=False,  # 热重载已启用
        log_level="info",
        access_log=True
    )