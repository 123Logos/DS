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

@router.get("/api/subsidy/points-value", response_model=ResponseModel, summary="查询当前积分值")
async def get_current_points_value(
    service: FinanceService = Depends(get_finance_service)
):
    """查询当前周补贴积分值配置（包括手动调整和自动计算值）"""
    try:
        data = service.get_current_points_value()
        return ResponseModel(
            success=True,
            message="查询成功",
            data=data
        )
    except Exception as e:
        logger.error(f"查询积分值失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
@router.post("/api/subsidy/points-value/adjust", response_model=ResponseModel, summary="调整积分值")
async def adjust_subsidy_points_value(
        points_value: Optional[float] = Query(None, ge=0, le=0.02,
                                              description="积分值（0-0.02），不传或传null取消手动调整"),
        auto_clear: bool = Query(True, description="是否在发放一次后自动清除，默认为true"),
        service: FinanceService = Depends(get_finance_service)
):
    """手动调整周补贴积分值（平台决策）"""
    try:
        success = service.adjust_subsidy_points_value(points_value, auto_clear)

        if points_value is None:
            message = "已取消积分值手动调整，恢复自动计算"
        else:
            message = f"周补贴积分值已调整为: {points_value:.4f}（{points_value * 100:.2f}%），auto_clear={auto_clear}"

        return ResponseModel(success=True, message=message)
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"调整积分值失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
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


# ========== 联创分红预览接口（已更新） ==========
@router.get("/api/reports/unilevel/preview", summary="联创分红预览（含用户上限）")
async def get_unilevel_dividend_preview(
        service: FinanceService = Depends(get_finance_service)
):
    """计算并展示联创星级分红预览（每个权重的金额，含单个用户1万上限）"""
    try:
        data = service.calculate_unilevel_dividend_preview()
        return {
            "success": True,
            "message": "分红预览计算成功",
            "data": data
        }
    except Exception as e:
        logger.error(f"分红预览计算失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/unilevel/adjust", response_model=ResponseModel, summary="调整联创分红金额（含上限预警）")
async def adjust_unilevel_dividend(
        amount_per_weight: Optional[float] = Query(None, ge=0, description="每个权重的分红金额（传入0或null取消调整）"),
        service: FinanceService = Depends(get_finance_service)
):
    """手动调整联创星级分红金额，如果存在用户会达到上限10,000元，将返回警告信息"""
    try:
        # 如果传入0，视为取消调整
        if amount_per_weight is not None and amount_per_weight <= 0:
            amount_per_weight = None

        result = service.adjust_unilevel_dividend_amount(amount_per_weight)

        # 构建响应
        response_data = {
            "amount_per_weight": amount_per_weight,
            "timestamp": datetime.now().isoformat()
        }

        # 如果有警告信息，添加到响应
        if result.get("warning"):
            response_data["warning"] = result["warning"]
            return ResponseModel(
                success=True,
                message=result["message"],
                data=response_data
            )
        else:
            return ResponseModel(
                success=True,
                message=result["message"],
                data=response_data
            )

    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"调整分红金额失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"调整失败: {str(e)}")


# ========== 执行联创分红接口（已增强） ==========
@router.post("/api/unilevel/dividend", summary="发放联创星级分红（手动触发）")
async def distribute_unilevel_dividend(
        service: FinanceService = Depends(get_finance_service)
):
    """手动触发联创星级分红发放（优先使用手动调整值）"""
    try:
        result = service.distribute_unilevel_dividend()
        if result:
            return {
                "success": True,
                "message": "联创星级分红发放成功"
            }
        return {
            "success": False,
            "message": "分红发放失败或无符合条件的用户"
        }
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
                "balance": str(balance),
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
                "change_amount": str(flow['change_amount']),
                "balance_after": str(flow['balance_after']) if flow['balance_after'] else None,
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
            "change_amount": str(item['change_amount']),
            "balance_after": str(item['balance_after']) if item['balance_after'] else None,
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


class AllocationsRequest(BaseModel):
    allocations: Dict[str, float]


@router.get("/api/fund-pools/allocations", response_model=ResponseModel, summary="查询资金池分配配置")
async def get_pool_allocations(
        service: FinanceService = Depends(get_finance_service)
):
    """获取当前资金池分配配置"""
    try:
        allocs = service.get_pool_allocations()
        # 同时查询每个资金池的当前余额，并构建返回结构
        data = {}
        for k, v in allocs.items():
            try:
                balance = service.get_account_balance(k)
            except Exception:
                balance = None
            data[k] = {"allocation": str(v), "balance": float(balance) if balance is not None else None}
        return ResponseModel(success=True, message="ok", data=data)
    except Exception as e:
        logger.error(f"获取资金池配置失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/fund-pools/allocations", response_model=ResponseModel, summary="更新资金池分配配置")
async def set_pool_allocations(
        request: AllocationsRequest,
        service: FinanceService = Depends(get_finance_service)
):
    """管理员更新资金池分配配置（会校验总和不超过20%）"""
    try:
        allocs = service.set_pool_allocations(request.allocations)
        data = {k: str(v) for k, v in allocs.items()}
        return ResponseModel(success=True, message="配置已更新", data=data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"更新资金池配置失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 1. 优惠券发放接口 ====================
# 在优惠券发放接口中添加 applicable_product_type 参数
@router.post("/api/coupons/distribute", response_model=ResponseModel, summary="直接发放优惠券")
async def distribute_coupon(
    user_id: int = Query(..., gt=0, description="用户ID"),
    amount: float = Query(..., gt=0, description="优惠券金额"),
    coupon_type: str = Query('user', pattern=r'^(user|merchant)$', description="优惠券类型"),
    applicable_product_type: str = Query('all', pattern=r'^(all|normal_only|member_only)$', description="适用商品范围：all=不限制，normal_only=仅普通商品，member_only=仅会员商品"),  # 新增参数
    service: FinanceService = Depends(get_finance_service)
):
    """直接给用户发放优惠券，需扣除等额的 true_total_points（1:1）"""
    try:
        coupon_id = service.distribute_coupon_directly(
            user_id,
            amount,
            coupon_type,
            applicable_product_type  # 传递新参数
        )
        return ResponseModel(
            success=True,
            message=f"优惠券发放成功（已扣除 true_total_points ¥{amount:.4f}）",
            data={"coupon_id": coupon_id, "amount": amount, "applicable_product_type": applicable_product_type}
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
    order_type: Optional[str] = Query(None, pattern=r'^(normal|member)$', description="订单商品类型（可选，用于验证优惠券适用范围）"),  # 新增参数
    service: FinanceService = Depends(get_finance_service)
):
    """使用优惠券，使其状态变为已使用（从列表消失）"""
    try:
        success = service.use_coupon(coupon_id, user_id, order_type)  # 传递订单类型
        if success:
            return ResponseModel(success=True, message="优惠券使用成功")
        else:
            raise HTTPException(status_code=500, detail="优惠券使用失败")
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"使用优惠券失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
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

# 在 api/finance/routes.py 中添加以下代码

# ==================== 平台积分余额查询接口 ====================
@router.get("/api/finance/points/company", response_model=ResponseModel, summary="查询平台积分余额")
async def get_company_points_balance(
    service: FinanceService = Depends(get_finance_service)
):
    """查询公司积分账户（company_points）的当前余额"""
    try:
        balance = service.get_account_balance('company_points')
        return ResponseModel(
            success=True,
            message="查询成功",
            data={
                "account_name": "公司积分账户",
                "account_type": "company_points",
                "balance": str(balance),
                "reserved": 0.0,
                "remark": "平台自有积分储备，用于积分抵扣等业务"
            }
        )
    except Exception as e:
        logger.error(f"查询平台积分余额失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 平台资金余额查询接口 ====================
@router.get("/api/finance/pool/platform-revenue", response_model=ResponseModel, summary="查询平台资金余额")
async def get_platform_revenue_balance(
    service: FinanceService = Depends(get_finance_service)
):
    """查询平台收入池（platform_revenue_pool）的当前余额"""
    try:
        balance = service.get_account_balance('platform_revenue_pool')
        return ResponseModel(
            success=True,
            message="查询成功",
            data={
                "account_name": "平台收入池",
                "account_type": "platform_revenue_pool",
                "balance": str(balance),
                "reserved": 0.0,
                "remark": "平台运营资金池，主要来源于商品销售收入的80%"
            }
        )
    except Exception as e:
        logger.error(f"查询平台资金余额失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# 在 api/finance/routes.py 中添加

@router.get("/api/reports/points/all-flows", response_model=ResponseModel, summary="综合点数流水报表")
async def get_all_points_flow_report(
        user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选）"),
        start_date: Optional[str] = Query(None, description="开始日期 yyyy-MM-dd"),
        end_date: Optional[str] = Query(None, description="结束日期 yyyy-MM-dd"),
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(20, ge=1, le=100, description="每页条数"),
        service: FinanceService = Depends(get_finance_service)
):
    try:
        data = service.get_all_points_flow_report_v2(
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            page=page,
            page_size=page_size
        )
        return ResponseModel(
            success=True,
            message=f"综合点数流水报表查询成功: 共{len(data['records'])}条记录",
            data=data
        )
    except Exception as e:
        logger.error(f"查询综合点数流水报表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
# ==================== 总会员积分明细报表接口 ====================
@router.get("/api/reports/points/member/detail", response_model=ResponseModel, summary="总会员积分明细报表")
async def get_member_points_detail_report(
        user_id: Optional[int] = Query(None, gt=0, description="用户ID（可选，查所有用户则留空）"),
        start_date: Optional[str] = Query(None, description="开始日期 yyyy-MM-dd"),
        end_date: Optional[str] = Query(None, description="结束日期 yyyy-MM-dd"),
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(20, ge=1, le=100, description="每页条数"),
        service: FinanceService = Depends(get_finance_service)
):
    """
    查询用户会员积分的详细流水

    功能特点：
    - 支持按用户ID、日期范围筛选
    - 自动计算期初余额和期末余额
    - 显示每条流水的收入/支出类型、金额、关联订单
    - 提供汇总统计（总收入、总支出、净变动）
    - 支持分页查询
    """
    try:
        data = service.get_member_points_detail_report(
            user_id=user_id,
            start_date=start_date,
            end_date=end_date,
            page=page,
            page_size=page_size
        )

        message = f"总会员积分明细报表查询成功"
        if user_id:
            message += f": 用户 {data['user_info']['user_name'] if data['user_info'] else user_id}"
        message += f"，共 {len(data['records'])} 条记录"

        return ResponseModel(
            success=True,
            message=message,
            data=data
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"查询总会员积分明细报表失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
@router.post("/api/donate/true-total-points", response_model=ResponseModel, summary="用户捐赠点数到公益基金")
async def donate_true_total_points(
    user_id: int = Query(..., gt=0, description="用户ID"),
    amount: float = Query(..., gt=0, description="捐赠金额"),
    service: FinanceService = Depends(get_finance_service)
):
    """
    用户将 true_total_points 捐赠到公益基金账户
    - 点数与资金1:1兑换
    - 同时记录用户点数减少和公益基金增加的流水
    - 可在公益基金流水中查询捐赠记录
    """
    try:
        result = service.donate_true_total_points(user_id, amount)
        return ResponseModel(
            success=True,
            message=result["message"],
            data=result
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"捐赠接口异常: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"捐赠失败: {str(e)}")
@router.get("/api/reports/platform/flow-summary", response_model=ResponseModel, summary="平台综合流水报表（一键整合）")
async def get_platform_flow_summary(
        start_date: str = Query(..., description="开始日期 yyyy-MM-dd"),
        end_date: str = Query(..., description="结束日期 yyyy-MM-dd"),
        user_id: Optional[int] = Query(None, gt=0, description="按用户ID筛选（可选）"),
        include_detail: bool = Query(True, description="是否包含明细记录"),
        page: int = Query(1, ge=1, description="页码"),
        page_size: int = Query(50, ge=1, le=200, description="每页条数"),
        service: FinanceService = Depends(get_finance_service)
):
    """
    平台综合流水报表（整合所有资金池、订单、积分、点数流水）

    功能特点：
    - 自动汇总所有资金池的收支情况
    - 关联订单、用户、操作类型
    - 智能识别资金流向（用户支付→平台→子池分配）
    - 支持按用户、日期范围筛选
    - 提供完整的余额快照和趋势分析
    """
    try:
        data = service.get_platform_flow_summary(
            start_date=start_date,
            end_date=end_date,
            user_id=user_id,
            include_detail=include_detail,
            page=page,
            page_size=page_size
        )

        total_pools = len(data['pools_summary'])
        total_records = data['pagination']['total']

        return ResponseModel(
            success=True,
            message=f"平台综合流水报表生成成功: {total_pools}个资金池, {total_records}笔交易",
            data=data
        )
    except FinanceException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"平台综合流水报表生成失败: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))
def register_finance_routes(app: FastAPI):
    """注册财务管理系统路由到主应用"""
    app.include_router(router, tags=["财务系统"])
