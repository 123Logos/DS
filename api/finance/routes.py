# api/finance/routes.py - 财务系统 API 路由
from typing import Optional, Dict, Any, List
from datetime import datetime
from decimal import Decimal

from fastapi import FastAPI, HTTPException, Depends, Query, Path, APIRouter
from fastapi.middleware.cors import CORSMiddleware

from core.database import get_conn
from core.logging import get_logger
from core.table_access import build_dynamic_select
from database_setup import DatabaseManager
from services.finance_service import FinanceService
from core.exceptions import FinanceException, OrderException
from core.config import PLATFORM_MERCHANT_ID, MEMBER_PRODUCT_PRICE, MAX_TEAM_LAYER
from models.schemas.finance import (
    ResponseModel, UserCreateRequest, ProductCreateRequest, OrderRequest,
    WithdrawalRequest, WithdrawalAuditRequest, RewardAuditRequest,
    CouponUseRequest, RefundRequest
)
from typing import List
from pydantic import BaseModel

logger = get_logger(__name__)

# 创建财务系统的路由
router = APIRouter()


def get_finance_service() -> FinanceService:
    """获取 FinanceService 实例（使用统一的 pymysql 连接）"""
    return FinanceService()


def get_database_manager() -> DatabaseManager:
    """获取 DatabaseManager 实例（用于数据库初始化）"""
    return DatabaseManager()


class ClearFundPoolsRequest(BaseModel):
    pool_types: List[str] = []  # 要清空的资金池类型列表


@router.get("/", summary="系统状态")
async def root():
    return {"message": "财务管理系统API运行中", "version": "3.2.0"}


@router.post("/api/init", response_model=ResponseModel, summary="初始化数据库")
async def init_database(db_manager: DatabaseManager = Depends(get_database_manager)):
    try:
        from core.database import get_conn
        with get_conn() as conn:
            with conn.cursor() as cursor:
                db_manager.init_all_tables(cursor)
            conn.commit()
        return ResponseModel(success=True, message="数据库初始化成功")
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
        raise HTTPException(status_code=500, detail=f"初始化失败: {e}")


"""@router.post("/api/init-data", response_model=ResponseModel, summary="创建测试数据")
async def create_test_data(db_manager: DatabaseManager = Depends(get_database_manager)):
    try:
        from core.database import get_conn
        with get_conn() as conn:
            with conn.cursor() as cursor:
                db_manager.init_all_tables(cursor)
                merchant_id = db_manager.create_test_data(cursor, conn)
            conn.commit()
        return ResponseModel(success=True, message="测试数据创建成功", data={"merchant_id": merchant_id})
    except Exception as e:
        logger.error(f"创建测试数据失败: {e}")
        raise HTTPException(status_code=500, detail=f"创建失败: {e}")


@router.post("/api/users", response_model=ResponseModel, summary="创建用户")
async def create_user(
        request: UserCreateRequest,
        service: FinanceService = Depends(get_finance_service)
):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (mobile, password_hash, name, status) VALUES (%s, %s, %s, 1)",
                    (request.mobile, '$2b$12$KZmw2fKkA7TczqQ8s8tK7e', request.name)
                )
                user_id = cur.lastrowid

                if request.referrer_id:
                    cur.execute(
                        "INSERT INTO user_referrals (user_id, referrer_id) VALUES (%s, %s)",
                        (user_id, request.referrer_id)
                    )

                conn.commit()
        return ResponseModel(success=True, message="用户创建成功", data={"user_id": user_id})
    except Exception as e:
        logger.error(f"创建用户失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))"""

"""@router.get("/api/users/{user_id}", response_model=ResponseModel, summary="查询用户信息")
async def get_user_info(
        user_id: int,
        service: FinanceService = Depends(get_finance_service)
):
    try:
        data = service.get_user_info(user_id)
        return ResponseModel(success=True, message="查询成功", data=data)
    except FinanceException as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"查询用户失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/users/set-referrer", response_model=ResponseModel, summary="设置推荐人")
async def set_user_referrer(
        service: FinanceService = Depends(get_finance_service),
        user_id: int = Query(..., gt=0, description="被推荐用户ID"),
        referrer_id: int = Query(..., gt=0, description="推荐人用户ID")
):
    try:
        #success = service.set_referrer(user_id, referrer_id)
        return ResponseModel(success=True, message="推荐关系设置成功")
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"设置推荐人失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/users/{user_id}/referrer", response_model=ResponseModel, summary="查询推荐人")
async def get_user_referrer(
        user_id: int,
        service: FinanceService = Depends(get_finance_service)
):
    try:
        referrer = service.get_user_referrer(user_id)
        if referrer:
            return ResponseModel(success=True, message="查询成功", data=referrer)
        return ResponseModel(success=True, message="该用户暂无推荐人", data=None)
    except Exception as e:
        logger.error(f"查询推荐人失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/users/{user_id}/team", response_model=ResponseModel, summary="查询团队下线")
async def get_user_team(
        service: FinanceService = Depends(get_finance_service),
        user_id: int = Path(..., gt=0),
        max_layer: int = Query(MAX_TEAM_LAYER, ge=1, le=MAX_TEAM_LAYER)
):
    try:
        team_members = service.get_user_team(user_id, max_layer)
        return ResponseModel(success=True, message="查询成功", data={"team": team_members})
    except Exception as e:
        logger.error(f"查询团队失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/products", response_model=ResponseModel, summary="创建商品")
async def create_product(
        product: ProductCreateRequest,
        service: FinanceService = Depends(get_finance_service)
):
    try:
        if product.merchant_id == PLATFORM_MERCHANT_ID:
            # 平台发布的商品，直接允许创建
            pass
        else:
            # 普通商家发布的商品，检查商家是否存在
            with get_conn() as conn:
                with conn.cursor() as cur:
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="id = %s",
                        select_fields=["id"]
                    )
                    cur.execute(select_sql, (product.merchant_id,))
                    if not cur.fetchone():
                        raise HTTPException(status_code=400, detail=f"商家不存在: {product.merchant_id}")

        # 确定商品价格
        if product.is_member_product == 1:
            final_price = float(MEMBER_PRODUCT_PRICE)
        else:
            final_price = product.price

        # 生成 SKU 并创建商品
        sku = f"SKU{int(datetime.now().timestamp())}"
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """"""INSERT INTO products (sku, name, price, stock, is_member_product, merchant_id, status)
                       VALUES (%s, %s, %s, %s, %s, %s, 1)""", """
                    (sku, product.name, final_price, product.stock, product.is_member_product, product.merchant_id)
                )
                product_id = cur.lastrowid
                conn.commit()
        return ResponseModel(success=True, message="商品创建成功", data={"product_id": product_id, "sku": sku})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"创建商品失败: {e}")
        raise HTTPException(status_code=400, detail=f"创建失败: {e}")


@router.get("/api/products", response_model=ResponseModel, summary="查询商品列表")
async def get_products(
        service: FinanceService = Depends(get_finance_service),
        is_member: Optional[int] = Query(None, ge=0, le=1)
):
    try:
        # 使用动态表访问获取商品信息
        with get_conn() as conn:
            with conn.cursor() as cur:
                where_clause = "status=1"
                params = []
                if is_member is not None:
                    where_clause += " AND is_member_product=%s"
                    params.append(is_member)
                
                select_sql = build_dynamic_select(
                    cur,
                    "products",
                    where_clause=where_clause,
                    select_fields=["id", "sku", "name", "price", "stock", "is_member_product", "merchant_id"]
                )
                cur.execute(select_sql, tuple(params))
                products = cur.fetchall()

        return ResponseModel(success=True, message="查询成功", data={
            "products": [{
                "id": p["id"],
                "sku": p.get("sku", ""),
                "name": p["name"],
                "price": float(p["price"]),
                "stock": p["stock"],
                "is_member_product": p["is_member_product"],
                "merchant_id": p["merchant_id"]
            } for p in products]
        })
    except Exception as e:
        logger.error(f"查询商品失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))"""

'''@router.post("/api/orders", response_model=ResponseModel, summary="订单结算")
async def settle_order(
        order: OrderRequest,
        service: FinanceService = Depends(get_finance_service)
):
    try:
        order_id = service.settle_order(**order.model_dump())
        return ResponseModel(success=True, message="订单结算成功", data={"order_id": order_id})
    except (OrderException, FinanceException) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"订单结算失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/orders/refund", response_model=ResponseModel, summary="订单退款")
async def refund_order(
        request: RefundRequest,
        service: FinanceService = Depends(get_finance_service)
):
    try:
        #success = service.refund_order(request.order_no)
        return ResponseModel(success=True, message="退款成功")
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"退款失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/orders/use-coupon", response_model=ResponseModel, summary="使用优惠券")
async def use_coupon(
        request: CouponUseRequest,
        service: FinanceService = Depends(get_finance_service)
):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 先获取表结构
                cur.execute("SHOW COLUMNS FROM coupons")
                columns = cur.fetchall()
                
                # 资产字段列表（金额相关字段）
                asset_fields = {'amount'}
                
                # 动态构造 SELECT 语句，对资产字段设置降级默认值
                from core.table_access import _quote_identifier

                select_parts = []
                for col in columns:
                    field_name = col['Field']
                    if field_name in asset_fields:
                        select_parts.append(f"COALESCE({_quote_identifier(field_name)}, 0) AS {_quote_identifier(field_name)}")
                    else:
                        select_parts.append(_quote_identifier(field_name))
                
                  select_sql = "SELECT " + ", ".join(select_parts)
                  query_sql = f"""{select_sql} FROM {_quote_identifier('coupons')} 
                       WHERE id = %s AND user_id = %s AND status = 'unused'
                       AND valid_from <= CURDATE() AND valid_to >= CURDATE()"""
                
                cur.execute(query_sql, (request.coupon_id, request.user_id))
                coupon = cur.fetchone()

                if not coupon:
                    raise HTTPException(status_code=400, detail="优惠券无效或已过期")

                discount_amount = Decimal(str(coupon['amount'] or 0))
                final_amount = max(Decimal('0.00'), Decimal(str(request.order_amount)) - discount_amount)

                cur.execute(
                    "UPDATE coupons SET status = 'used', used_at = NOW() WHERE id = %s",
                    (request.coupon_id,)
                )
                conn.commit()

        return ResponseModel(
            success=True,
            message="优惠券使用成功",
            data={"final_amount": float(final_amount), "discount": float(discount_amount)}
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"使用优惠券失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/submit-test-order", response_model=ResponseModel, summary="提交测试订单")
async def submit_test_order(
        service: FinanceService = Depends(get_finance_service),
        user_id: int = Query(..., gt=0, description="用户ID"),
        product_type: str = Query(..., pattern=r'^(member|normal)$', description="商品类型"),
        quantity: int = Query(1, ge=1, description="数量"),
        points_to_use: float = Query(0, ge=0, description="使用积分数，支持小数点后4位精度")
):
    try:
        is_member = 1 if product_type == "member" else 0

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT id, price, name FROM products WHERE is_member_product = %s AND status = 1 LIMIT 1""",
                    (is_member,)
                )
                product = cur.fetchone()

                if not product:
                    if product_type == "member":
                        sku = f"SKU-M-{int(datetime.now().timestamp())}"
                        cur.execute(
                            """INSERT INTO products (sku, name, price, stock, is_member_product, merchant_id, status)
                               VALUES (%s, %s, %s, 100, 1, %s, 1)""",
                            (sku, '会员星卡', float(MEMBER_PRODUCT_PRICE), PLATFORM_MERCHANT_ID)
                        )
                        product_id = cur.lastrowid
                        price = float(MEMBER_PRODUCT_PRICE)
                        product_name = '会员星卡'
                        conn.commit()
                    else:
                        raise HTTPException(status_code=404, detail="暂无普通商品")
                else:
                    product_id = product["id"]
                    price = float(product["price"])
                    product_name = product["name"]

        order_no = f"TEST{datetime.now().strftime('%Y%m%d%H%M%S')}"


        return ResponseModel(
            success=True,
            message="测试订单提交成功",
            data={
                "order_no": order_no,
                "product_id": product_id,
                "product_name": product_name,
                "amount": price,
                "quantity": quantity,
                "is_member_product": is_member
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"提交测试订单失败: {e}")
        raise HTTPException(status_code=400, detail=str(e))'''


@router.post("/api/subsidy/distribute", response_model=ResponseModel, summary="发放周补贴")
async def distribute_subsidy(
        service: FinanceService = Depends(get_finance_service)
):
    """手动触发周补贴发放（发放 subsidy_points 专用点数）"""
    try:
        success = service.distribute_weekly_subsidy()
        if success:
            return ResponseModel(success=True, message="周补贴发放成功（增加 subsidy_points）")
        else:
            raise HTTPException(status_code=500, detail="补贴发放失败，请检查日志")
    except Exception as e:
        logger.error(f"周补贴失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 周补贴预览报表接口（全用户） ====================
@router.get("/api/reports/subsidy/preview/weekly", response_model=ResponseModel, summary="周积分预览报表（全用户）")
async def get_weekly_subsidy_preview(
    year: int = Query(..., ge=2024, description="年份，如2025"),
    week: int = Query(..., ge=1, le=53, description="周数，1-53"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: FinanceService = Depends(get_finance_service)
):
    """查询所有用户在指定周的积分余额和预计可获得的周补贴金额（支持分页）"""
    try:
        data = service.get_weekly_subsidy_preview(year, week, page, page_size)
        return ResponseModel(
            success=True,
            message=f"全用户周补贴预览报表查询成功: 共{len(data['user_records'])}条记录",
            data=data
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"周补贴预览报表查询失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/unilevel/dividend", response_model=ResponseModel, summary="发放联创星级分红（手动触发）")
async def distribute_unilevel_dividend(
    service: FinanceService = Depends(get_finance_service)
):
    """手动触发联创星级分红发放"""
    try:
        # 每次调用创建新实例避免连接污染
        result = service.distribute_unilevel_dividend()
        if result:
            return ResponseModel(success=True, message="联创星级分红发放成功")
        return ResponseModel(success=False, message="分红发放失败或无符合条件的用户")
    except Exception as e:
        logger.error(f"联创分红接口异常: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/subsidy/fund", response_model=ResponseModel, summary="预存补贴资金")
async def fund_subsidy_pool(
        service: FinanceService = Depends(get_finance_service),
        amount: float = Query(10000, gt=0)
):
    try:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE finance_accounts SET balance = %s WHERE account_type = 'subsidy_pool'",
                    (amount,)
                )
                conn.commit()
        return ResponseModel(success=True, message=f"补贴池已预存¥{amount:.2f}")
    except Exception as e:
        logger.error(f"预存补贴失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/public-welfare", response_model=ResponseModel, summary="查询公益基金余额")
async def get_public_welfare_balance(
        service: FinanceService = Depends(get_finance_service)
):
    try:
        balance = service.get_public_welfare_balance()
        return ResponseModel(
            success=True,
            message="查询成功",
            data={
                "account_name": "公益基金",
                "account_type": "public_welfare",
                "balance": float(balance),
                "reserved": 0.0,
                "remark": "该账户自动汇入1%交易额"
            }
        )
    except Exception as e:
        logger.error(f"查询公益基金余额失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/public-welfare/flow", response_model=ResponseModel, summary="公益基金流水明细")
async def get_public_welfare_flow(
        limit: int = Query(50, description="返回条数"),
        service: FinanceService = Depends(get_finance_service)
):
    try:
        flows = service.get_public_welfare_flow(limit)

        def get_user_name(uid):
            if not uid:
                return "系统"
            try:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        select_sql = build_dynamic_select(
                            cur,
                            "users",
                            where_clause="id = %s",
                            select_fields=["name"]
                        )
                        cur.execute(select_sql, (uid,))
                        row = cur.fetchone()
                        return row["name"] if row else "未知用户"
            except Exception as e:
                return f"未知用户:{e}"

        data = {
            "flows": [{
                "id": flow['id'],
                "related_user": flow['related_user'],
                "user_name": get_user_name(flow['related_user']),
                "change_amount": float(flow['change_amount']),
                "balance_after": float(flow['balance_after']) if flow['balance_after'] else None,
                "flow_type": flow['flow_type'],
                "remark": flow['remark'],
                "created_at": flow['created_at'].strftime("%Y-%m-%d %H:%M:%S") if isinstance(flow['created_at'],
                                                                                             datetime) else str(
                    flow['created_at'])
            } for flow in flows]
        }
        return ResponseModel(success=True, message="查询成功", data=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/reports/public-welfare", response_model=ResponseModel, summary="公益基金交易报表")
async def get_public_welfare_report(
        start_date: str = Query(..., description="开始日期 yyyy-MM-dd"),
        end_date: str = Query(..., description="结束日期 yyyy-MM-dd"),
        service: FinanceService = Depends(get_finance_service)
):
    try:
        report_data = service.get_public_welfare_report(start_date, end_date)

        def get_user_name(uid):
            if not uid:
                return "系统"
            try:
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        select_sql = build_dynamic_select(
                            cur,
                            "users",
                            where_clause="id = %s",
                            select_fields=["name"]
                        )
                        cur.execute(select_sql, (uid,))
                        row = cur.fetchone()
                        return row["name"] if row else "未知用户"
            except Exception as e:
                return f"未知用户:{e}"

        details = [{
            **item,
            "user_name": get_user_name(item['related_user']),
            "change_amount": float(item['change_amount']),
            "balance_after": float(item['balance_after']) if item['balance_after'] else None,
            "created_at": item['created_at'].strftime("%Y-%m-%d %H:%M:%S") if isinstance(item['created_at'],
                                                                                         datetime) else str(
                item['created_at'])
        } for item in report_data['details']]

        return ResponseModel(
            success=True,
            message="查询成功",
            data={"summary": report_data['summary'], "details": details}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/api/withdrawals/audit", response_model=ResponseModel, summary="审核提现")
async def audit_withdrawal(
        request: WithdrawalAuditRequest,
        service: FinanceService = Depends(get_finance_service)
):
    """审核提现申请"""
    try:
        success = service.audit_withdrawal(
            withdrawal_id=request.withdrawal_id,
            approve=request.approve,
            auditor=request.auditor
        )

        if success:
            action = "批准" if request.approve else "拒绝"
            return ResponseModel(success=True, message=f"提现已{action}")
        else:
            raise HTTPException(status_code=500, detail="审核失败，请检查日志")

    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"提现审核失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"审核异常: {str(e)}")


@router.get("/api/rewards/pending", response_model=ResponseModel, summary="查询奖励列表")
async def get_pending_rewards(
        service: FinanceService = Depends(get_finance_service),
        status: str = Query('pending', pattern=r'^(pending|approved|rejected)$'),
        reward_type: Optional[str] = Query(None, pattern=r'^(referral|team)$'),
        limit: int = Query(50, ge=1, le=200)
):
    try:
        rewards = service.get_rewards_by_status(status, reward_type, limit)
        return ResponseModel(success=True, message="查询成功", data={"rewards": rewards})
    except Exception as e:
        logger.error(f"查询奖励列表失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 周补贴点数报表接口 ====================
@router.get("/api/reports/points/subsidy", response_model=ResponseModel, summary="周补贴用户点数报表")
async def get_subsidy_points_report(
        user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
        service: FinanceService = Depends(get_finance_service)
):
    """查询周补贴点数明细"""
    try:
        data = service.get_subsidy_points_report(user_id)
        return ResponseModel(
            success=True,
            message=f"周补贴点数报表查询成功: 共{len(data['users'])}个用户",
            data=data
        )
    except Exception as e:
        logger.error(f"查询周补贴点数报表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ==================== 联创星级点数报表接口 ====================
@router.get("/api/reports/points/unilevel", response_model=ResponseModel, summary="联创星级用户点数报表")
async def get_unilevel_points_report(
        user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
        service: FinanceService = Depends(get_finance_service)
):
    """查询联创星级点数明细"""
    try:
        data = service.get_unilevel_points_report(user_id)
        return ResponseModel(
            success=True,
            message=f"联创星级点数报表查询成功: 共{len(data['users'])}个用户",
            data=data
        )
    except Exception as e:
        logger.error(f"查询联创星级点数报表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 推荐+团队合并点数报表接口 ====================
@router.get("/api/reports/points/referral-team", response_model=ResponseModel, summary="推荐+团队合并用户点数报表")
async def get_referral_and_team_points_report(
        user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
        service: FinanceService = Depends(get_finance_service)
):
    """
    查询推荐奖励和团队奖励合并点数报表

    返回三项数据：
    1. referral_points - 推荐奖励点数
    2. team_points - 团队奖励点数
    3. combined_total - 推荐和团队点数合计
    """
    try:
        data = service.get_referral_and_team_points_report(user_id)
        return ResponseModel(
            success=True,
            message=f"推荐+团队合并点数报表查询成功: 共{len(data['users'])}个用户",
            data=data
        )
    except Exception as e:
        logger.error(f"查询推荐+团队合并点数报表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
# ==================== 所有点数流水报表接口 ====================
@router.get("/api/reports/points/all", response_model=ResponseModel, summary="所有点数流水报表")
async def get_all_points_flow_report(
    user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
    service: FinanceService = Depends(get_finance_service)
):
    """查询所有点数类型的流水报表（周补贴、推荐奖励、团队奖励、联创星级），包括没有点数的用户"""
    try:
        data = service.get_all_points_flow_report(user_id)
        return ResponseModel(
            success=True,
            message=f"所有点数流水报表查询成功: 共{len(data['users'])}个用户",
            data=data
        )
    except Exception as e:
        logger.error(f"查询所有点数流水报表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
@router.get("/api/reports/finance", response_model=ResponseModel, summary="财务总览报告")
async def get_finance_report(
        service: FinanceService = Depends(get_finance_service)
):
    try:
        data = service.get_finance_report()
        return ResponseModel(success=True, message="报告生成成功", data=data)
    except Exception as e:
        logger.error(f"生成财务报告失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/reports/account-flow", response_model=ResponseModel, summary="资金流水报告")
async def get_account_flow_report(
        limit: int = Query(50, ge=1, le=1000),
        service: FinanceService = Depends(get_finance_service)
):
    try:
        flows = service.get_account_flow_report(limit)
        return ResponseModel(success=True, message="流水查询成功", data={"flows": flows})
    except Exception as e:
        logger.error(f"查询资金流水失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/reports/points-flow", response_model=ResponseModel, summary="积分流水报告")
async def get_points_flow_report(
        user_id: Optional[int] = Query(None, gt=0),
        limit: int = Query(50, ge=1, le=1000),
        service: FinanceService = Depends(get_finance_service)
):
    try:
        flows = service.get_points_flow_report(user_id, limit)
        return ResponseModel(success=True, message="积分流水查询成功", data={"flows": flows})
    except Exception as e:
        logger.error(f"查询积分流水失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/reports/points-deduction", response_model=ResponseModel, summary="积分抵扣明细报表")
async def get_points_deduction_report(
        start_date: str = Query(..., description="开始日期 yyyy-MM-dd"),
        end_date: str = Query(..., description="结束日期 yyyy-MM-dd"),
        page: int = Query(1, ge=1),
        page_size: int = Query(20, ge=1, le=100),
        service: FinanceService = Depends(get_finance_service)
):
    try:
        data = service.get_points_deduction_report(start_date, end_date, page, page_size)
        return ResponseModel(success=True, message="查询成功", data=data)
    except Exception as e:
        logger.error(f"查询积分抵扣报表失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ==================== 订单积分流水报告接口 ====================
@router.get("/api/reports/order-points", response_model=ResponseModel, summary="订单积分流水报告")
async def get_order_points_flow_report(
    start_date: str = Query(..., description="开始日期 yyyy-MM-dd"),
    end_date: str = Query(..., description="结束日期 yyyy-MM-dd"),
    user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
    order_no: Optional[str] = Query(None, description="订单号（可选）"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: FinanceService = Depends(get_finance_service)
):
    """查询订单相关的积分流动情况，包括用户积分、商户积分和积分抵扣"""
    try:
        data = service.get_order_points_flow_report(
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            order_no=order_no,
            page=page,
            page_size=page_size
        )
        return ResponseModel(
            success=True,
            message=f"订单积分流水报告查询成功: 共{len(data['records'])}条记录",
            data=data
        )
    except Exception as e:
        logger.error(f"订单积分流水报告查询失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
@router.get("/api/admin/reports/transaction-chain", response_model=ResponseModel, summary="交易推荐链报表")
async def get_transaction_chain_report(
        user_id: int = Query(..., gt=0, description="购买者ID"),
        order_no: Optional[str] = Query(None, description="订单号（可选）"),
        service: FinanceService = Depends(get_finance_service)
):
    try:
        data = service.get_transaction_chain_report(user_id, order_no)
        return ResponseModel(success=True, message="查询成功", data=data)
    except FinanceException as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"查询交易链报表失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/fund-pools/clear", response_model=ResponseModel, summary="清空指定资金池")
async def clear_fund_pools(
        request: ClearFundPoolsRequest,
        service: FinanceService = Depends(get_finance_service)
):
    """手动清空指定的资金池"""
    try:
        result = service.clear_fund_pools(request.pool_types)

        return ResponseModel(
            success=True,
            message=f"已清空 {len(result['cleared_pools'])} 个资金池，总计 ¥{result['total_cleared']:.2f}",
            data=result
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"清空资金池接口异常: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 1. 优惠券发放接口 ====================
@router.post("/api/coupons/distribute", response_model=ResponseModel, summary="直接发放优惠券")
async def distribute_coupon(
    user_id: int = Query(..., gt=0, description="用户ID"),
    amount: float = Query(..., gt=0, description="优惠券金额"),
    coupon_type: str = Query('user', pattern=r'^(user|merchant)$', description="优惠券类型"),
    service: FinanceService = Depends(get_finance_service)
):
    """直接给用户发放优惠券，无需审核流程"""
    try:
        coupon_id = service.distribute_coupon_directly(user_id, amount, coupon_type)
        return ResponseModel(
            success=True,
            message=f"优惠券发放成功",
            data={"coupon_id": coupon_id, "amount": amount}
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"发放优惠券失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"发放失败: {str(e)}")


# ==================== 2. 推荐奖励接口 ====================
@router.get("/api/rewards/referral", response_model=ResponseModel, summary="查询推荐奖励")
async def get_referral_rewards(
    user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
    status: str = Query('approved', pattern=r'^(approved|all)$', description="奖励状态"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: FinanceService = Depends(get_finance_service)
):
    """查询推荐奖励自动发放记录（发放到 referral_points）"""
    try:
        data = service.get_referral_rewards(user_id, status, page, page_size)
        return ResponseModel(
            success=True,
            message="查询成功（奖励已自动发放到 referral_points）",
            data=data
        )
    except Exception as e:
        logger.error(f"查询推荐奖励失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 3. 推荐和团队奖励流水接口 ====================
@router.get("/api/rewards/flow", response_model=ResponseModel, summary="奖励流水明细")
async def get_reward_flow(
    user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
    reward_type: Optional[str] = Query(None, pattern=r'^(referral|team)$', description="奖励类型"),
    start_date: Optional[str] = Query(None, description="开始日期 yyyy-MM-dd"),
    end_date: Optional[str] = Query(None, description="结束日期 yyyy-MM-dd"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: FinanceService = Depends(get_finance_service)
):
    """查询奖励自动发放流水明细（从 account_flow 查询）"""
    try:
        data = service.get_reward_flow_report(
            user_id=user_id,
            reward_type=reward_type,
            start_date=start_date,
            end_date=end_date,
            page=page,
            page_size=page_size
        )
        return ResponseModel(
            success=True,
            message=f"奖励流水查询成功: 共{len(data['records'])}条记录",
            data=data
        )
    except Exception as e:
        logger.error(f"查询奖励流水失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 9. 优惠券使用后消失接口 ====================
@router.post("/api/coupons/use", response_model=ResponseModel, summary="使用优惠券")
async def use_coupon(
    coupon_id: int = Query(..., gt=0, description="优惠券ID"),
    user_id: int = Query(..., gt=0, description="用户ID"),
    service: FinanceService = Depends(get_finance_service)
):
    """使用优惠券，使其状态变为已使用（从列表消失）"""
    try:
        success = service.use_coupon(coupon_id, user_id)
        if success:
            return ResponseModel(success=True, message="优惠券使用成功")
        else:
            raise HTTPException(status_code=500, detail="优惠券使用失败")
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"使用优惠券失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ... 在 clear_fund_pools 接口之后添加 ...

@router.get("/api/reports/subsidy/weekly", response_model=ResponseModel, summary="周补贴明细报表")
async def get_weekly_subsidy_report(
        year: int = Query(..., ge=2024, description="年份，如2025"),
        week: int = Query(..., ge=1, le=53, description="周数，1-53"),
        user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(20, ge=1, le=100, description="每页条数"),
        service: FinanceService = Depends(get_finance_service)
):
    """查询指定周次的补贴发放明细

    可按用户筛选，支持分页。返回汇总统计和明细列表。
    """
    try:
        data = service.get_weekly_subsidy_report(year, week, user_id, page, page_size)
        return ResponseModel(
            success=True,
            message=f"周补贴报表查询成功: {data['summary']['query_week']}",
            data=data
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"周补贴报表查询失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/reports/subsidy/monthly", response_model=ResponseModel, summary="月补贴明细报表")
async def get_monthly_subsidy_report(
        year: int = Query(..., ge=2024, description="年份，如2025"),
        month: int = Query(..., ge=1, le=12, description="月份，1-12"),
        user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(20, ge=1, le=100, description="每页条数"),
        service: FinanceService = Depends(get_finance_service)
):
    """查询指定月份的补贴发放明细

    显示该月内所有周次的补贴记录，可按用户筛选，支持分页。
    """
    try:
        data = service.get_monthly_subsidy_report(year, month, user_id, page, page_size)
        return ResponseModel(
            success=True,
            message=f"月补贴报表查询成功: {data['summary']['query_month']}",
            data=data
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"月补贴报表查询失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# api/finance/routes.py

# ... 在 subsidy/monthly 接口之后添加 ...

@router.get("/api/reports/points/member/weekly", response_model=ResponseModel, summary="用户积分周报表")
async def get_weekly_member_points_report(
        year: int = Query(..., ge=2024, description="年份，如2025"),
        week: int = Query(..., ge=1, le=53, description="周数，1-53"),
        user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(20, ge=1, le=100, description="每页条数"),
        service: FinanceService = Depends(get_finance_service)
):
    """查询指定周次的用户积分变动明细"""
    try:
        data = service.get_weekly_member_points_report(year, week, user_id, page, page_size)
        return ResponseModel(
            success=True,
            message=f"用户积分周报表查询成功: {data['summary']['query_week']}",
            data=data
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"用户积分周报表查询失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/reports/points/member/monthly", response_model=ResponseModel, summary="用户积分月报表")
async def get_monthly_member_points_report(
        year: int = Query(..., ge=2024, description="年份，如2025"),
        month: int = Query(..., ge=1, le=12, description="月份，1-12"),
        user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(20, ge=1, le=100, description="每页条数"),
        service: FinanceService = Depends(get_finance_service)
):
    """查询指定月份的用户积分变动明细"""
    try:
        data = service.get_monthly_member_points_report(year, month, user_id, page, page_size)
        return ResponseModel(
            success=True,
            message=f"用户积分月报表查询成功: {data['summary']['query_month']}",
            data=data
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"用户积分月报表查询失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/reports/points/merchant/weekly", response_model=ResponseModel, summary="商家积分周报表")
async def get_weekly_merchant_points_report(
        year: int = Query(..., ge=2024, description="年份，如2025"),
        week: int = Query(..., ge=1, le=53, description="周数，1-53"),
        user_id: Optional[int] = Query(None, gt=0, description="商家用户ID（可选）"),
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(20, ge=1, le=100, description="每页条数"),
        service: FinanceService = Depends(get_finance_service)
):
    """查询指定周次的商家积分变动明细"""
    try:
        data = service.get_weekly_merchant_points_report(year, week, user_id, page, page_size)
        return ResponseModel(
            success=True,
            message=f"商家积分周报表查询成功: {data['summary']['query_week']}",
            data=data
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"商家积分周报表查询失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/reports/points/merchant/monthly", response_model=ResponseModel, summary="商家积分月报表")
async def get_monthly_merchant_points_report(
        year: int = Query(..., ge=2024, description="年份，如2025"),
        month: int = Query(..., ge=1, le=12, description="月份，1-12"),
        user_id: Optional[int] = Query(None, gt=0, description="商家用户ID（可选）"),
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(20, ge=1, le=100, description="每页条数"),
        service: FinanceService = Depends(get_finance_service)
):
    """查询指定月份的商家积分变动明细"""
    try:
        data = service.get_monthly_merchant_points_report(year, month, user_id, page, page_size)
        return ResponseModel(
            success=True,
            message=f"商家积分月报表查询成功: {data['summary']['query_month']}",
            data=data
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"商家积分月报表查询失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

# ==================== 联创星级点数流水报表接口 ====================
@router.get("/api/reports/unilevel/points-flow", response_model=ResponseModel, summary="联创星级点数流水报表")
async def get_unilevel_points_flow_report(
    user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
    level: Optional[int] = Query(None, ge=1, le=3, description="星级（1-3，可选）"),
    start_date: Optional[str] = Query(None, description="开始日期 yyyy-MM-dd"),
    end_date: Optional[str] = Query(None, description="结束日期 yyyy-MM-dd"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: FinanceService = Depends(get_finance_service)
):
    """查询联创星级分红点数的流水明细"""
    try:
        data = service.get_unilevel_points_flow_report(
            user_id=user_id,
            level=level,
            start_date=start_date,
            end_date=end_date,
            page=page,
            page_size=page_size
        )
        return ResponseModel(
            success=True,
            message=f"联创星级点数流水报表查询成功: 共{len(data['records'])}条记录",
            data=data
        )
    except Exception as e:
        logger.error(f"查询联创星级点数流水报表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
# ==================== 1. 提现申请处理报表接口 ====================
@router.get("/api/reports/withdrawal", response_model=ResponseModel, summary="提现申请处理报表")
async def get_withdrawal_report(
    start_date: str = Query(..., description="开始日期 yyyy-MM-dd"),
    end_date: str = Query(..., description="结束日期 yyyy-MM-dd"),
    user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
    status: Optional[str] = Query(None, pattern=r'^(pending_auto|pending_manual|approved|rejected)$', description="状态筛选"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: FinanceService = Depends(get_finance_service)
):
    """查询提现申请的处理情况统计和明细"""
    try:
        data = service.get_withdrawal_report(
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            status=status,
            page=page,
            page_size=page_size
        )
        return ResponseModel(
            success=True,
            message=f"提现申请报表查询成功: 共{len(data['records'])}条记录",
            data=data
        )
    except Exception as e:
        logger.error(f"查询提现申请报表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 2. 平台资金池变动报表接口 ====================
@router.get("/api/reports/pool-flow", response_model=ResponseModel, summary="平台资金池变动报表")
async def get_pool_flow_report(
    account_type: str = Query(..., pattern=r'^(public_welfare|subsidy_pool|honor_director|company_points|platform_revenue_pool)$', description="资金池类型"),
    start_date: str = Query(..., description="开始日期 yyyy-MM-dd"),
    end_date: str = Query(..., description="结束日期 yyyy-MM-dd"),
    page: int = Query(1, ge=1, description="页码"),
    page_size: int = Query(20, ge=1, le=100, description="每页条数"),
    service: FinanceService = Depends(get_finance_service)
):
    """查询指定资金池的流水明细和汇总统计"""
    try:
        data = service.get_pool_flow_report(
            account_type=account_type,
            start_date=start_date,
            end_date=end_date,
            page=page,
            page_size=page_size
        )
        return ResponseModel(
            success=True,
            message=f"资金池流水报表查询成功: {data['summary']['account_name']}",
            data=data
        )
    except Exception as e:
        logger.error(f"查询资金池流水报表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
def register_finance_routes(app: FastAPI):
    """注册财务管理系统路由到主应用"""
    app.include_router(router, tags=["财务系统"])
