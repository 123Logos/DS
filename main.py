"""
统一的应用入口 - 集中创建 FastAPI 实例和配置
"""
import sys
from pathlib import Path
import uvicorn
import pymysql
from fastapi import FastAPI, Response, HTTPException
from fastapi.openapi.docs import get_swagger_ui_html, get_swagger_ui_oauth2_redirect_html, get_redoc_html
from fastapi.responses import HTMLResponse, FileResponse
import re
from core.json_response import DecimalJSONResponse, register_exception_handlers
from fastapi.staticfiles import StaticFiles
from core.middleware import setup_cors, setup_static_files, setup_request_id
OPENAPI_PATH = "/openapi.json"
from core.health import router as health_router
from core.config import get_db_config, PIC_PATH, AVATAR_UPLOAD_DIR, UVICORN_PORT, settings
from core.logging import setup_logging
from database_setup import initialize_database
from core.startup_checks import validate_production_safety
from api.wechat_pay.routes import register_wechat_pay_routes
from api.wechat_wxa.routes import register_wechat_wxa_routes
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
from api.offline.routes import register_offline_routes, pay_bridge_router
from api.order.refund import router as refund_router   # ✅ 新增导入
from api.security.routes import register_security_routes

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
    title="禹泽数字科技综合管理系统API",
    description="本网站为企业综合管理系统接口服务平台，用于提供用户管理、订单管理、商品管理及数据统计等系统功能。",
    version="1.0.0",
    # 必须为 None：否则内置 /docs 会先注册，自定义备案页永远不会被匹配到
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    default_response_class=DecimalJSONResponse
)
# 注册全局异常处理器（放在 core/json_response.py 中实现）
register_exception_handlers(app)


# 在每次应用启动时初始化数据库表结构（幂等）
@app.on_event("startup")
def on_startup():
    logger.info("=" * 50)
    logger.info("应用启动：检查并初始化数据库表结构与后台任务")
    try:
        validate_production_safety()
    except RuntimeError as e:
        logger.critical("启动配置校验失败: %s", e)
        raise

    if settings.RUN_MIGRATE_ON_STARTUP and not settings.SKIP_STARTUP_DDL:
        try:
            from scripts.migrate import run_migrations

            run_migrations()
            logger.info("启动迁移脚本执行完成")
        except Exception as e:
            logger.warning("启动迁移脚本失败（可稍后手动执行 migrate.py）: %s", e)

    if not settings.SKIP_STARTUP_DDL:
        try:
            initialize_database()
            logger.info("数据库表结构初始化完成")
        except Exception as e:
            logger.error("初始化数据库失败: %s", e, exc_info=True)
    else:
        logger.info("SKIP_STARTUP_DDL=1，跳过 on_startup 表结构初始化")

    try:
        from core.auth import refresh_sessions_table_cache

        refresh_sessions_table_cache()
    except Exception as e:
        logger.warning("刷新 sessions 表缓存失败: %s", e)

    try:
        from api.order.order import start_order_expire_task

        start_order_expire_task()
    except Exception as e:
        logger.error("启动订单过期任务失败: %s", e)

    try:
        from database_setup import start_background_tasks

        start_background_tasks()
        logger.info("后台定时任务已启动")
    except Exception as e:
        logger.error("启动后台定时任务失败: %s", e, exc_info=True)
    logger.info("=" * 50)

    # 启动时刷新快递公司列表缓存
    '''try:
        from api.order.wechat_shipping import WechatShippingManager
        WechatShippingManager.refresh_delivery_list_cache()
        logger.info("启动时已刷新快递公司列表缓存")
    except Exception as e:
        logger.warning(f"刷新快递公司列表缓存失败: {e}")'''

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
    {
        "name": "微信小程序",
        "description": "小程序服务器消息推送（发货管理事件等），与支付回调 URL 独立配置。",
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

# 挂载 ``/offline`` 静态目录（子路径如 /offline/xxx.txt；精确路径 /offline?id= 由 pay_bridge_router 处理）
# 用于放置微信小程序域名校验等文件。
offline_static_dir = Path("offline")
offline_static_dir.mkdir(exist_ok=True)
_APP_ROOT = Path(__file__).resolve().parent


def _domain_verify_txt_response(filename: str) -> FileResponse:
    """域名校验文件：依次查找项目根目录、offline/（与 StaticFiles 挂载一致）。"""
    for p in (_APP_ROOT / filename, offline_static_dir / filename):
        if p.is_file():
            return FileResponse(str(p), media_type="text/plain; charset=utf-8")
    raise HTTPException(status_code=404, detail="Not Found")


@app.get("/senIScNn8d.txt", include_in_schema=False)
async def wechat_mp_domain_verify_txt():
    """
    微信校验常要求访问 https://域名/senIScNn8d.txt。
    依次查找：项目根目录（与历史部署一致）、offline/（与静态挂载一致）。
    """
    return _domain_verify_txt_response("senIScNn8d.txt")


@app.get("/52c061f087c7465664f22c9344178416.txt", include_in_schema=False)
async def wechat_mp_domain_verify_52c061f_txt():
    """业务域名校验等由平台生成的根路径文件名；文件可放在项目根或 offline/。"""
    return _domain_verify_txt_response("52c061f087c7465664f22c9344178416.txt")


# /offline?id= 永久收款 H5 落地（pay_bridge_router）必须优先于下方 StaticFiles，否则无法匹配
app.include_router(pay_bridge_router)

app.mount("/offline", StaticFiles(directory=str(offline_static_dir)), name="offline_static")

setup_request_id(app)
setup_cors(app)
setup_static_files(app)
app.include_router(health_router)

# 注册所有模块的路由（必须在设置 custom_openapi 之前注册）
register_finance_routes(app)
register_user_routes(app)
register_order_routes(app)
register_product_routes(app)
register_system_routes(app)
register_wechat_applyment_routes(app)  # 添加这一行
register_wechat_pay_routes(app)
register_wechat_wxa_routes(app)
register_store_routes(app)
register_bankcard_routes(app) # 修改：注册新的银行卡路由
register_offline_routes(app)
register_security_routes(app)

# ✅ 注册退款路由（根路径 + /api 前缀，兼容不同前端请求；标准路径另有 /refund/*）
# 必须传 tags，否则 operation 无 tags，Swagger UI 会归到「default」分组
app.include_router(refund_router, tags=["订单系统"])
app.include_router(refund_router, prefix="/api", tags=["订单系统"])

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


# Serve the sensitive txt file contents in plain text
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    try:
        # 获取原始 Swagger UI HTML
        swagger_html = get_swagger_ui_html(
            openapi_url=OPENAPI_PATH,
            title=f"{app.title} - Swagger UI",
            oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
            init_oauth=app.swagger_ui_init_oauth,
            swagger_ui_parameters=app.swagger_ui_parameters,
        )
        # 确保 body 存在
        if not swagger_html.body:
            raise ValueError("Swagger UI HTML body is empty")
        original_html = swagger_html.body.decode('utf-8')
    except Exception as e:
        logger.error(f"Failed to get Swagger UI HTML: {e}", exc_info=True)
        # 出错时返回原始响应（不带备案号），保证页面正常显示
        return get_swagger_ui_html(
            openapi_url=OPENAPI_PATH,
            title=f"{app.title} - Swagger UI",
            oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
            init_oauth=app.swagger_ui_init_oauth,
            swagger_ui_parameters=app.swagger_ui_parameters,
        )

    beian_html = """
    <div style="
        position: fixed;
        bottom: 0;
        left: 0;
        right: 0;
        text-align: center;
        font-size: 12px;
        color: #666;
        background: rgba(255,255,255,0.95);
        padding: 8px;
        z-index: 10000;
        border-top: 1px solid #e2e2e2;
    ">
        <a href="https://beian.miit.gov.cn/" target="_blank" rel="noopener noreferrer" style="color: #3b82f6; text-decoration: none;">
            鄂ICP备2026001452号
        </a>
    </div>
    """

    # 不区分大小写替换 </body>
    original_html = re.sub(r'</body>', beian_html + '</body>', original_html, flags=re.IGNORECASE)

    logger.info("Injected beian HTML into /docs")
    return HTMLResponse(content=original_html, media_type="text/html")


# Swagger UI oauth2 redirect 支持
@app.get(app.swagger_ui_oauth2_redirect_url, include_in_schema=False)
async def swagger_ui_redirect():
    return get_swagger_ui_oauth2_redirect_html()


# ReDoc 页面（全文搜索），保留在 /redoc
@app.get("/redoc", include_in_schema=False)
async def redoc_html():
    return get_redoc_html(openapi_url=OPENAPI_PATH, title=f"{app.title} - ReDoc")


@app.get(OPENAPI_PATH, include_in_schema=False)
async def openapi_json():
    return app.openapi()


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