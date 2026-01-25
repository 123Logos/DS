# finance_service.py - 已同步database_setup字段变更
# **重要变更说明**：
# 1. 原points字段不再参与积分运算，所有积分逻辑改用member_points（会员积分）
# 2. 所有积分字段类型为DECIMAL(12,4)，需使用Decimal类型处理，禁止int()转换
# 3. merchant_points同步支持小数精度处理

import logging
import json
from decimal import Decimal
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import time
import pymysql
from core.config import (
    AllocationKey, ALLOCATIONS, MAX_POINTS_VALUE, TAX_RATE,
    POINTS_DISCOUNT_RATE, MEMBER_PRODUCT_PRICE, COUPON_VALID_DAYS,
    PLATFORM_MERCHANT_ID, MAX_PURCHASE_PER_DAY, MAX_TEAM_LAYER,
    LOG_FILE
)
from core.database import get_conn
from core.db_adapter import PyMySQLAdapter
from core.exceptions import FinanceException, OrderException, InsufficientBalanceException
from core.logging import get_logger
from core.table_access import build_dynamic_select, get_table_structure, _quote_identifier
from core.table_access import build_dynamic_select, get_table_structure, _quote_identifier, build_select_list
from core.db_adapter import build_in_placeholders

logger = get_logger(__name__)


class FinanceService:
    def __init__(self, session: Optional[PyMySQLAdapter] = None):
        """
        初始化 FinanceService

        Args:
            session: 数据库会话适配器，如果为 None 则自动创建
        """
        self.session = session or PyMySQLAdapter()

    def _check_pool_balance(self, account_type: str, required_amount: Decimal) -> bool:
        balance = self.get_account_balance(account_type)
        if balance < required_amount:
            raise InsufficientBalanceException(account_type, required_amount, balance)
        return True

    def _check_user_balance(self, user_id: int, required_amount: Decimal,
                            balance_type: str = 'promotion_balance') -> bool:
        balance = self.get_user_balance(user_id, balance_type)
        if balance < required_amount:
            raise InsufficientBalanceException(f"user:{user_id}:{balance_type}", required_amount, balance)
        return True

    def check_purchase_limit(self, user_id: int) -> bool:
        return True

    def get_account_balance(self, account_type: str) -> Decimal:
        """直接获取连接，绕过 PyMySQLAdapter 的连接管理问题"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT balance FROM finance_accounts WHERE account_type = %s",
                        (account_type,)
                    )
                    row = cur.fetchone()
                    # 使用字典访问方式，避免 RowProxy 的属性访问问题
                    balance_val = row.get('balance') if row else 0
                    return Decimal(str(balance_val)) if balance_val is not None else Decimal('0')
        except Exception as e:
            logger.error(f"查询账户余额失败: {e}")
            return Decimal('0')

    def get_user_balance(self, user_id: int, balance_type: str = 'promotion_balance') -> Decimal:
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 使用动态表访问，自动处理字段不存在的情况
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="id=%s",
                        select_fields=[balance_type]
                    )
                    cur.execute(select_sql, (user_id,))
                    row = cur.fetchone()
                    val = row.get(balance_type, 0) if row else 0
                    return Decimal(str(val))
        except Exception as e:
            logger.error(f"查询用户余额失败: {e}")
            return Decimal('0')

    # ==================== 新增：资金池余额检查辅助方法 ====================
    def _ensure_pool_balance(self, account_type: str, amount_to_deduct: Decimal) -> None:
        """
        确保资金池余额充足，防止扣成负数

        Args:
            account_type: 资金池类型
            amount_to_deduct: 要扣减的金额（正值）

        Raises:
            InsufficientBalanceException: 如果余额不足
        """
        if amount_to_deduct <= 0:
            return  # 不需要扣减，直接返回

        current_balance = self.get_account_balance(account_type)
        logger.debug(f"检查资金池余额: {account_type} 当前余额: {current_balance}, 需要扣减: {amount_to_deduct}")

        if current_balance < amount_to_deduct:
            raise InsufficientBalanceException(
                f"finance_account:{account_type}",
                amount_to_deduct,
                current_balance,
                message=f"资金池 {account_type} 余额不足，当前: {current_balance:.4f}，需要扣减: {amount_to_deduct:.4f}"
            )
       # ==================== 关键修改：支持外部连接复用，分离优惠券逻辑 ====================
    def settle_order(self, order_no: str, user_id: int, order_id: int,
                     points_to_use: Decimal = Decimal('0'),
                     coupon_discount: Decimal = Decimal('0'),
                     external_conn=None) -> int:
        """订单结算（多商品版本：支持遍历所有商品分别计算奖励）"""
        logger.debug(f"订单结算开始: {order_no}, 积分抵扣={points_to_use}, 优惠券抵扣={coupon_discount}")

        # 使用外部连接（如果有），避免嵌套事务
        if external_conn:
            conn = external_conn
            cursor = conn.cursor()
            try:
                return self._settle_order_internal(cursor, order_no, user_id, order_id,
                                                   points_to_use, coupon_discount)
            finally:
                cursor.close()
        else:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    return self._settle_order_internal(cur, order_no, user_id, order_id,
                                                       points_to_use, coupon_discount)

    def _settle_order_internal(self, cur, order_no: str, user_id: int, order_id: int,
                               points_to_use: Decimal, coupon_discount: Decimal) -> int:
        """多商品订单结算核心逻辑（最终修复版：按单件商品计算奖励）"""
        try:
            # 1. 查询所有订单商品（不再只处理第一件）
            cur.execute(
                """SELECT oi.product_id, oi.quantity, oi.unit_price, 
                          p.is_member_product
                   FROM order_items oi
                   JOIN products p ON oi.product_id = p.id
                   WHERE oi.order_id = %s""",
                (order_id,)
            )
            order_items = cur.fetchall()

            if not order_items:
                raise OrderException(f"订单无商品明细: {order_no}")

            # 2. 查询用户信息
            select_sql = build_dynamic_select(
                cur, "users",
                where_clause="id=%s",
                select_fields=["member_level", "member_points"]
            )
            cur.execute(select_sql, (user_id,))
            user_row = cur.fetchone()
            if not user_row:
                raise OrderException(f"用户不存在: {user_id}")

            user = type('obj', (object,), {
                'member_level': user_row.get('member_level', 0) or 0,
                'member_points': Decimal(str(user_row.get('member_points', 0) or 0))
            })()

            # 3. 分类统计商品和计算奖励基数
            total_amount = Decimal('0')
            member_items = []
            single_member_price = Decimal('0')

            for item in order_items:
                item_total = Decimal(str(item['unit_price'])) * Decimal(str(item['quantity']))
                total_amount += item_total

                if item['is_member_product']:
                    member_items.append(item)
                    if single_member_price == Decimal('0'):
                        single_member_price = Decimal(str(item['unit_price']))

            # 4. 计算优惠抵扣（积分 + 优惠券）
            points_discount = points_to_use * POINTS_DISCOUNT_RATE
            total_discount = points_discount + coupon_discount

            if total_discount > total_amount:
                raise OrderException("优惠金额不能超过订单总额")

            final_amount = total_amount - total_discount

            logger.debug(
                f"订单金额计算: 商品总额¥{total_amount}, 奖励基数¥{single_member_price}, "
                f"积分抵扣¥{points_discount}, 优惠券抵扣¥{coupon_discount}, 实付¥{final_amount}"
            )

            # 5. 处理积分抵扣（只处理真实积分）
            if points_to_use > Decimal('0'):
                self._apply_points_discount_v2(cur, user_id, user, points_to_use, total_amount, order_id)

            # 6. 更新订单主表
            cur.execute(
                """UPDATE orders SET 
                   merchant_id=%s, total_amount=%s, original_amount=%s,
                   points_discount=%s, status='pending_ship', updated_at=NOW()
                   WHERE order_number=%s""",
                (PLATFORM_MERCHANT_ID, final_amount, total_amount, total_discount, order_no)
            )

            # 7. 处理会员商品（整个订单级别一次性处理奖励）
            if member_items:
                total_member_quantity = sum(int(item['quantity']) for item in member_items)

                # 升级会员等级
                old_level = user.member_level
                new_level = min(old_level + total_member_quantity, 6)

                cur.execute(
                    "UPDATE users SET member_level = %s, level_changed_at = NOW() WHERE id = %s",
                    (new_level, user_id)
                )

                # 发放用户积分（基于实付金额比例）
                if final_amount > Decimal('0'):
                    member_total_amount = sum(
                        Decimal(str(item['unit_price'])) * Decimal(str(item['quantity']))
                        for item in member_items
                    )
                    points_ratio = member_total_amount / total_amount if total_amount > 0 else Decimal('1')
                    member_points_earned = final_amount * points_ratio

                    cur.execute(
                        "UPDATE users SET member_points = COALESCE(member_points, 0) + %s WHERE id = %s",
                        (member_points_earned, user_id)
                    )

                    cur.execute(
                        """INSERT INTO points_log (user_id, change_amount, balance_after, type, reason, related_order, created_at)
                           VALUES (%s, %s, (SELECT COALESCE(member_points,0) FROM users WHERE id = %s), 'member', %s, %s, NOW())""",
                        (user_id, member_points_earned, user_id, '购买会员商品获得积分', order_id)
                    )
                    logger.debug(f"用户{user_id}获得积分: +{member_points_earned:.4f}")

                # 发放推荐和团队奖励（传递单件价格和总数量）
                if total_member_quantity > 0 and single_member_price > Decimal('0'):
                    self._create_pending_rewards_v2(
                        cur, order_id, user_id, old_level, new_level,
                        single_member_price,
                        total_member_quantity
                    )

            # 8. 处理普通商品（不发放奖励，只发积分）
            normal_items = [item for item in order_items if not item['is_member_product']]
            if normal_items:
                normal_total_amount = sum(
                    Decimal(str(item['unit_price'])) * Decimal(str(item['quantity']))
                    for item in normal_items
                )

                if user.member_level >= 1 and final_amount > Decimal('0'):
                    points_ratio = normal_total_amount / total_amount if total_amount > 0 else Decimal('0')
                    normal_points_earned = final_amount * points_ratio

                    cur.execute(
                        "UPDATE users SET member_points = COALESCE(member_points, 0) + %s WHERE id = %s",
                        (normal_points_earned, user_id)
                    )

                    cur.execute(
                        """INSERT INTO points_log (user_id, change_amount, balance_after, type, reason, related_order, created_at)
                           VALUES (%s, %s, (SELECT COALESCE(member_points,0) FROM users WHERE id = %s), 'member', %s, %s, NOW())""",
                        (user_id, normal_points_earned, user_id, '购买普通商品获得积分', order_id)
                    )
                    logger.debug(f"用户{user_id}获得积分: +{normal_points_earned:.4f}")

            # 9. 记录完整用户支付链路（100% 收入 → 80% 商家 + 20% 各池）
            allocs = self.get_pool_allocations()
            platform_revenue = final_amount  # ① 先按 100% 记收入
            self._add_pool_balance(cur, 'platform_revenue_pool', platform_revenue,
                                   f"订单#{order_id} 用户支付¥{final_amount:.2f}", user_id)

            # ② 再记 20% 支出（分配到各子池）
            for atype, ratio in allocs.items():
                if atype == 'merchant_balance':
                    continue
                alloc_amount = final_amount * ratio
                self._add_pool_balance(cur, 'platform_revenue_pool', -alloc_amount,
                                       f"订单#{order_id} 分配到{atype}池¥{alloc_amount:.2f}", user_id)
                # 各子池收入
                self._add_pool_balance(cur, atype, alloc_amount,
                                       f"订单#{order_id} 子池收入¥{alloc_amount:.2f}", user_id)

            # 记录流水
            cur.execute("SELECT balance FROM finance_accounts WHERE account_type = 'platform_revenue_pool'")
            new_balance = Decimal(str(cur.fetchone()['balance'] or 0))

            cur.execute(
                """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                   flow_type, remark, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                ('platform_revenue_pool', PLATFORM_MERCHANT_ID, platform_revenue,
                 new_balance, 'income', f"订单#{order_id} 平台收入¥{platform_revenue:.2f}")
            )

            # 公司积分池增加：基于订单总额扣除积分抵扣后的基数的20%
            try:
                company_base = total_amount - points_discount
                if company_base < Decimal('0'):
                    company_base = Decimal('0')
                company_points = (company_base * Decimal('0.20')).quantize(Decimal('0.0001'))

                cur.execute(
                    "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'company_points'",
                    (company_points,)
                )
                cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", ('company_points',))
                cp_row = cur.fetchone()
                cp_new_balance = Decimal(str(cp_row['balance'] or 0))

                cur.execute(
                    """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                       flow_type, remark, created_at)
                       VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                    ('company_points', PLATFORM_MERCHANT_ID, company_points, cp_new_balance, 'income', f"订单#{order_id} 公司积分池+20% ¥{company_points:.4f}")
                )
                logger.debug(f"公司积分池增加: ¥{company_points:.4f}（订单#{order_id}）")
                # 在积分流水中记录公司积分池的变动（便于积分报表追踪）
                try:
                    cur.execute(
                        "INSERT INTO points_log (user_id, change_amount, balance_after, type, reason, related_order, created_at) VALUES (%s, %s, %s, %s, %s, %s, NOW())",
                        (PLATFORM_MERCHANT_ID, company_points, cp_new_balance, 'company', f"订单#{order_id} 公司积分池增加", order_id)
                    )
                except Exception as e:
                    logger.debug(f"写入 points_log（公司积分池）失败: {e}")
            except Exception as e:
                logger.error(f"更新公司积分池失败: {e}")

            # 10. 使用动态配置分配其他资金池（按 account_type 的 allocation）
            try:
                pools_cfg = allocs
            except Exception:
                pools_cfg = None

            if pools_cfg:
                for atype, ratio in pools_cfg.items():
                    if atype == 'merchant_balance':
                        continue
                    try:
                        alloc_amount = final_amount * ratio
                        cur.execute(
                            "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
                            (alloc_amount, atype)
                        )
                        cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", (atype,))
                        new_balance = Decimal(str(cur.fetchone()['balance'] or 0))
                        cur.execute(
                            """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                               flow_type, remark, created_at)
                               VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                            (atype, PLATFORM_MERCHANT_ID, alloc_amount, new_balance, 'income', f"订单#{order_id} {atype}池¥{alloc_amount:.2f}")
                        )
                    except Exception as e:
                        logger.error(f"动态分配到池子 {atype} 失败: {e}")
            else:
                # 回退到旧的 ALLOCATIONS 配置
                for purpose, percent in ALLOCATIONS.items():
                    if purpose == AllocationKey.PLATFORM_REVENUE_POOL:
                        continue
                    alloc_amount = final_amount * percent
                    cur.execute(
                        "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
                        (alloc_amount, purpose.value)
                    )
                    cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", (purpose.value,))
                    new_balance = Decimal(str(cur.fetchone()['balance'] or 0))
                    cur.execute(
                        """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                           flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                        (purpose.value, PLATFORM_MERCHANT_ID, alloc_amount,
                         new_balance, 'income', f"订单#{order_id} {purpose.value}池¥{alloc_amount:.2f}")
                    )

            logger.debug(f"订单结算成功: ID={order_id}, 奖励基数¥{single_member_price}")
            return order_id

        except Exception as e:
            logger.error(f"订单结算失败: {e}", exc_info=True)
            raise

    # ==================== 积分抵扣逻辑（v2版本） ====================
    def _apply_points_discount_v2(self, cur, user_id: int, user, points_to_use: Decimal, amount: Decimal,
                                  order_id: int) -> None:
        """积分抵扣处理（v2：接受cursor参数）"""
        user_points = Decimal(str(user.member_points))
        if user_points < points_to_use:
            raise OrderException(f"积分不足，当前{user_points:.4f}分")

        # 扣减member_points
        cur.execute(
            "UPDATE users SET member_points = member_points - %s WHERE id = %s AND member_points >= %s",
            (points_to_use, user_id, points_to_use)
        )
        if cur.rowcount == 0:
            # 说明积分不足或被并发消费
            raise OrderException(f"积分不足或并发冲突，无法使用{points_to_use:.4f}分")

        # 【关键修复】获取扣减后的余额用于记录流水
        cur.execute(
            "SELECT member_points FROM users WHERE id = %s",
            (user_id,)
        )
        new_balance = Decimal(str(cur.fetchone()['member_points'] or 0))

        # 【关键修复】记录用户积分扣减流水
        cur.execute(
            """INSERT INTO points_log 
               (user_id, change_amount, balance_after, type, reason, related_order, created_at)
               VALUES (%s, %s, %s, 'member', %s, %s, NOW())""",
            (user_id, -points_to_use, new_balance, '积分抵扣支付', order_id)
        )

        # 更新公司积分池（累计到公司积分）
        cur.execute(
            "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'company_points'",
            (points_to_use,)
        )
        # 记录资金池流水
        cur.execute(
            """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
               flow_type, remark, created_at)
               VALUES (%s, %s, %s, 
                      (SELECT balance FROM finance_accounts WHERE account_type = 'company_points'), 
                      %s, %s, NOW())""",
            ('company_points', user_id, points_to_use, 'income', f"用户{user_id}积分抵扣转入")
        )

        # 同步写入积分流水表，记录公司积分池的增加（设 user_id 为平台ID以示系统入账）
        try:
            cur.execute(
                "INSERT INTO points_log (user_id, change_amount, balance_after, type, reason, related_order, created_at) VALUES (%s, %s, (SELECT balance FROM finance_accounts WHERE account_type = 'company_points'), %s, %s, %s, NOW())",
                (PLATFORM_MERCHANT_ID, points_to_use, 'company', f"用户{user_id}积分抵扣转入公司池", None)
            )
        except Exception as e:
            logger.debug(f"写入 points_log（用户积分抵扣->公司池）失败: {e}")

    # ==================== 会员订单处理（v2版本） ====================
    # def _process_member_order_v2(self, cur, order_id: int, user_id: int, user,
    #                              unit_price: Decimal, quantity: int,
    #                              final_amount: Decimal,
    #                              points_discount: Decimal,
    #                              coupon_discount: Decimal) -> None:
    #     total_amount = unit_price * quantity
    #
    #     # 1. 资金池分配
    #     self._allocate_funds_to_pools_v2(cur, order_id, total_amount)
    #
    #     # 2. 升级会员等级
    #     old_level = user.member_level
    #     new_level = min(old_level + quantity, 6)
    #     cur.execute(
    #         "UPDATE users SET member_level = %s, level_changed_at = NOW() WHERE id = %s",
    #         (new_level, user_id)
    #     )
    #
    #     # 3. ✅ 立即发放用户积分（基于实付金额）
    #     points_earned = final_amount
    #     if points_earned > Decimal('0'):
    #         cur.execute(
    #             "UPDATE users SET member_points = COALESCE(member_points, 0) + %s WHERE id = %s",
    #             (points_earned, user_id)
    #         )
    #
    #         # 记录积分流水
    #         cur.execute(
    #             """INSERT INTO points_log (user_id, change_amount, balance_after, type, reason, related_order, created_at)
    #                VALUES (%s, %s, (SELECT COALESCE(member_points,0) FROM users WHERE id = %s), 'member', %s, %s, NOW())""",
    #             (user_id, points_earned, user_id, '购买会员商品获得积分', order_id)
    #         )
    #         logger.debug(f"用户{user_id}获得积分: +{points_earned:.4f}")
    #
    #     # 4. ✅ 关键：立即发放推荐和团队奖励（基于商品固定价格）
    #     self._create_pending_rewards_v2(cur, order_id, user_id, old_level, new_level, unit_price)
    #
    #     # 5. 公司积分池增加
    #     # 计算逻辑改为
    #     real_points_discount = points_discount - coupon_discount  # 纯积分抵扣
    #     company_points = (total_amount - real_points_discount) * Decimal('0.20')
    #     cur.execute(
    #         "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'company_points'",
    #         (company_points,)
    #     )
    #
    #     # 记录流水
    #     cur.execute("SELECT balance FROM finance_accounts WHERE account_type = 'company_points'", ('company_points',))
    #     new_balance = Decimal(str(cur.fetchone()['balance'] or 0))
    #     cur.execute(
    #         """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after,
    #            flow_type, remark, created_at)
    #            VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
    #         ('company_points', user_id, company_points, new_balance, 'income',
    #          f"会员订单#{order_id} 公司积分（销售金额¥{total_amount:.2f}的20%）")
    #     )
    #
    #     logger.debug(f"用户升级: {old_level}星 → {new_level}星, 所有奖励已立即发放")
    #
    # ==================== 普通订单处理（v2版本） ====================
    # def _process_normal_order_v2(self, cur, order_id: int, user_id: int, merchant_id: int,
    #                              final_amount: Decimal, original_amount: Decimal,
    #                              points_discount: Decimal,
    #                              coupon_discount: Decimal,  # 新增
    #                              member_level: int) -> None:
    #     # 1. 平台池子分配
    #     platform_amount = final_amount
    #     cur.execute(
    #         "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'platform_revenue_pool'",
    #         (platform_amount,)
    #     )
    #     logger.debug(f"平台收入池增加: ¥{platform_amount:.4f}")
    #
    #     # 2. 从平台收入池分配到其他池子
    #     for purpose, percent in ALLOCATIONS.items():
    #         if purpose == AllocationKey.PLATFORM_REVENUE_POOL:
    #             continue
    #         alloc_amount = final_amount * percent
    #         cur.execute(
    #             "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
    #             (alloc_amount, purpose.value)
    #         )
    #         logger.debug(f"池子分配 {purpose.value}: ¥{alloc_amount:.4f}")
    #
    #     # 3. ✅ 立即发放用户积分（会员等级≥1的用户）
    #     if member_level >= 1:
    #         points_earned = final_amount
    #         cur.execute(
    #             "UPDATE users SET member_points = COALESCE(member_points, 0) + %s WHERE id = %s",
    #             (points_earned, user_id)
    #         )
    #         # 记录积分流水
    #         cur.execute(
    #             """INSERT INTO points_log (user_id, change_amount, balance_after, type, reason, related_order, created_at)
    #                VALUES (%s, %s, (SELECT COALESCE(member_points,0) FROM users WHERE id = %s), 'member', %s, %s, NOW())""",
    #             (user_id, points_earned, user_id, '购买获得积分', order_id)
    #         )
    #         logger.debug(f"用户{user_id}获得积分: +{points_earned:.4f}")
    #
    #     # 4. 商户积分发放（平台自营，省略）
    #
    #     # 5. 公司积分池增加
    #     # 计算逻辑改为
    #     real_points_discount = points_discount - coupon_discount
    #     platform_merchant_points = (original_amount - real_points_discount) * Decimal('0.20')
    #     cur.execute(
    #         "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'company_points'",
    #         (platform_merchant_points,)
    #     )
    #     logger.debug(f"公司积分池增加: {platform_merchant_points:.4f}")

    # ==================== 资金池分配（v2版本） ====================
    def _allocate_funds_to_pools_v2(self, cur, order_id: int, total_amount: Decimal) -> None:
        """资金池分配（v2：修复版，为所有池子写入流水）"""
        # 读取运行时配置
        allocs = self.get_pool_allocations()

        # 商家/平台收入部分使用 merchant_balance
        platform_revenue = total_amount * allocs.get('merchant_balance', Decimal('0.80'))

        # 更新平台收入池余额
        cur.execute(
            "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'platform_revenue_pool'",
            (platform_revenue,)
        )

        # ==================== 关键修复：查询余额并写入流水 ====================
        cur.execute("SELECT balance FROM finance_accounts WHERE account_type = 'platform_revenue_pool'")
        new_balance = Decimal(str(cur.fetchone()['balance'] or 0))

        cur.execute(
            """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
               flow_type, remark, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
            ('platform_revenue_pool', PLATFORM_MERCHANT_ID, platform_revenue,
             new_balance, 'income', f"会员订单#{order_id} 平台收入¥{platform_revenue:.2f}")
        )
        logger.debug(f"平台收入池增加: {platform_revenue:.4f}（已写入流水）")

        # 使用动态配置按行分配到各池子（排除 merchant_balance）
        for atype, ratio in allocs.items():
            if atype == 'merchant_balance':
                continue
            try:
                alloc_amount = total_amount * ratio

                # 确保对应的 finance_accounts 行存在
                cur.execute(
                    "INSERT INTO finance_accounts (account_name, account_type, balance) VALUES (%s, %s, 0) ON DUPLICATE KEY UPDATE account_name=VALUES(account_name)",
                    (atype, atype)
                )

                cur.execute(
                    "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
                    (alloc_amount, atype)
                )

                cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", (atype,))
                new_balance = Decimal(str(cur.fetchone()['balance'] or 0))

                cur.execute(
                    """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                       flow_type, remark, created_at)
                       VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                    (atype, PLATFORM_MERCHANT_ID, alloc_amount, new_balance, 'income', f"会员订单#{order_id} {atype}池¥{alloc_amount:.2f}")
                )
                logger.debug(f"池子 {atype} 增加: {alloc_amount:.4f}（已写入流水）")
            except Exception as e:
                logger.error(f"分配到池子 {atype} 失败: {e}")

    def _create_pending_rewards_v2(self, cur, order_id: int, buyer_id: int,
                                   old_level: int, new_level: int,
                                   single_price: Decimal, total_quantity: int) -> None:
        """
        创建推荐和团队奖励（严格层级版）

        核心修复：
        1. 团队奖励必须由≥目标层级的用户获得（L2奖励只能由L2+用户获得）
        2. 如果第N层用户不满足星级，则向上寻找该层的"替代者"
        3. 防止低层级用户获得高层级奖励（如L1用户拿L2奖励）

        业务规则：
        - 推荐奖励：仅首次购买（0星→1星）且直接推荐人≥1星时发放
        - 团队奖励：只为新达到的层级发放，必须由≥目标层级的用户获得
        """
        logger.info(f"开始发放奖励: 订单#{order_id}, 购买者={buyer_id}({old_level}→{new_level}星)")

        # ==================== 防重复检查 ====================
        cur.execute(
            """SELECT id FROM account_flow 
               WHERE account_type IN ('referral_points', 'team_reward_points') 
               AND remark LIKE %s
               LIMIT 1""",
            (f"%订单#{order_id}%",)
        )
        if cur.fetchone():
            logger.warning(f"⚠️ 订单#{order_id}的奖励已发放过，跳过重复发放")
            return
        # ===================================================

        total_distributed = Decimal('0')
        referral_paid = False  # 防止推荐奖励和团队奖励同时触发

        # 1. 推荐奖励（首次购买 + 推荐人必须是星级会员）
        if old_level == 0:  # 只有0星升1星时才发推荐奖励
            cur.execute(
                "SELECT referrer_id FROM user_referrals WHERE user_id = %s",
                (buyer_id,)
            )
            referrer = cur.fetchone()

            if referrer and referrer['referrer_id']:
                cur.execute(
                    "SELECT member_level FROM users WHERE id = %s",
                    (referrer['referrer_id'],)
                )
                referrer_info = cur.fetchone()
                referrer_level = referrer_info['member_level'] if referrer_info else 0

                if referrer_level >= 1:
                    reward_amount = single_price * Decimal('0.50')

                    # 发放到 referral_points
                    cur.execute(
                        "UPDATE users SET referral_points = COALESCE(referral_points, 0) + %s WHERE id = %s",
                        (reward_amount, referrer['referrer_id'])
                    )
                    # 更新 true_total_points
                    cur.execute(
                        "UPDATE users SET true_total_points = true_total_points + %s WHERE id = %s",
                        (reward_amount, referrer['referrer_id'])
                    )

                    # 记录流水
                    cur.execute(
                        "SELECT COALESCE(referral_points, 0) AS referral_points FROM users WHERE id = %s",
                        (referrer['referrer_id'],)
                    )
                    new_balance = Decimal(str(cur.fetchone()['referral_points'] or 0))

                    cur.execute(
                        """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                           flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                        ('referral_points', referrer['referrer_id'], reward_amount,
                         new_balance, 'income', f"推荐奖励 - 订单#{order_id}")
                    )

                    logger.info(f"推荐奖励发放: 用户{referrer['referrer_id']}({referrer_level}星) +{reward_amount:.2f}")
                    total_distributed += reward_amount
                    referral_paid = True
                else:
                    logger.debug(f"推荐人{referrer['referrer_id']}不是星级会员({referrer_level}星)，不发放推荐奖励")
            else:
                logger.debug("购买者无推荐人，跳过推荐奖励")

        # 2. 团队奖励（只为新达到的层级发放；0→1 也发放），且不与推荐奖励同发
        if referral_paid:
            logger.debug("已发放推荐奖励，本次跳过团队奖励")
            return

        # 继续判断是否提升等级
        # 2. 团队奖励（只为新达到的层级发放；0→1 也发放）
        if new_level <= old_level:
            logger.debug("等级未提升，不产生团队奖励")
            return

        # ==================== 计算新达到的层级范围 ====================
        start_layer = max(old_level + 1, 1)  # 允许 0→1 发放 L1 团队奖励
        logger.debug(f"发放团队奖励层级范围: L{start_layer}-L{new_level}")
        # ========================================================================

        # ==================== 核心修复：构建完整推荐链 ============================
        current_id = buyer_id
        referrer_chain = []  # 存储完整的推荐链
        visited = {buyer_id}  # 防止自指或循环

        for current_layer in range(1, MAX_TEAM_LAYER + 1):
            cur.execute(
                "SELECT referrer_id FROM user_referrals WHERE user_id = %s",
                (current_id,)
            )
            ref = cur.fetchone()

            if not ref or not ref['referrer_id']:
                logger.debug(f"第{current_layer}层无推荐人，链断裂")
                break

            referrer_id = ref['referrer_id']

            # 避免自指或循环导致自己拿团队奖
            if referrer_id in visited:
                logger.debug(f"推荐链出现自指/循环（用户{referrer_id}），停止发放团队奖励")
                break
            visited.add(referrer_id)
            cur.execute("SELECT member_level FROM users WHERE id = %s", (referrer_id,))
            user_row = cur.fetchone()
            referrer_level = user_row.get('member_level', 0) if user_row else 0

            referrer_chain.append({
                'layer': current_layer,
                'user_id': referrer_id,
                'member_level': referrer_level
            })

            logger.debug(f"第{current_layer}层: 用户{referrer_id}({referrer_level}星)")
            current_id = referrer_id

        if not referrer_chain:
            logger.debug("推荐链为空，无法发放团队奖励")
            return
        # ========================================================================

        # ==================== 核心修复：严格层级查找 ===============================
        # 错误版：if candidate['layer'] > target_layer: continue  # 错误地允许L1用户拿L2奖励
        # 正确版：if candidate['layer'] < target_layer: continue  # L2奖励只能由L2+用户获得

        for target_layer in range(start_layer, new_level + 1):
            reward_recipient = None

            # 在完整推荐链中查找满足条件的推荐人（按层级从小到大）
            for candidate in referrer_chain:
                # ==================== 关键修复：层级限制 ============================
                # 错误逻辑：允许低层级用户拿高层级奖励
                # if candidate['layer'] > target_layer:
                #     continue

                # 正确逻辑：奖励必须由≥目标层级的用户获得
                if candidate['layer'] < target_layer:
                    continue  # L2奖励不能由L1用户获得
                # ====================================================================

                if candidate['user_id'] == buyer_id:
                    continue  # 仅本人一人时不发团队奖励给自己

                if candidate['member_level'] >= target_layer:
                    # 找到第一个满足条件的用户（按层数从小到大）
                    reward_recipient = {
                        'user_id': candidate['user_id'],
                        'actual_layer': candidate['layer'],
                        'member_level': candidate['member_level']
                    }
                    logger.debug(
                        f"找到满足条件的推荐人: 用户{candidate['user_id']}（第{candidate['layer']}层，{candidate['member_level']}星）")
                    break

            if not reward_recipient:
                logger.debug(f"第{target_layer}层无满足星级{target_layer}的推荐人，跳过")
                continue

            # ==================== 发放奖励 ====================
            recipient_id = reward_recipient['user_id']
            actual_layer = reward_recipient['actual_layer']

            reward_amount = single_price * Decimal('0.50')

            # 发放到 team_reward_points
            cur.execute(
                "UPDATE users SET team_reward_points = COALESCE(team_reward_points, 0) + %s WHERE id = %s",
                (reward_amount, recipient_id)
            )
            # 更新 true_total_points
            cur.execute(
                "UPDATE users SET true_total_points = true_total_points + %s WHERE id = %s",
                (reward_amount, recipient_id)
            )

            # 记录流水
            cur.execute(
                "SELECT COALESCE(team_reward_points, 0) AS team_reward_points FROM users WHERE id = %s",
                (recipient_id,)
            )
            new_balance = Decimal(str(cur.fetchone()['team_reward_points'] or 0))

            cur.execute(
                """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                   flow_type, remark, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                ('team_reward_points', recipient_id, reward_amount,
                 new_balance, 'income', f"团队L{target_layer}奖励（来自第{actual_layer}层）- 订单#{order_id}")
            )

            total_distributed += reward_amount
            logger.info(
                f"团队奖励发放: 用户{recipient_id}（第{actual_layer}层）获得L{target_layer}奖励 {reward_amount:.2f}")

        logger.info(f"奖励发放完成: 订单#{order_id}共发放{total_distributed:.2f}点数")

    # ==================== 关键修改3：member_points积分发放 ====================
    def _allocate_funds_to_pools(self, order_id: int, total_amount: Decimal) -> None:
        try:
            allocs = self.get_pool_allocations()
            platform_revenue = total_amount * allocs.get('merchant_balance', Decimal('0.80'))
        except Exception:
            allocs = None
            platform_revenue = total_amount * Decimal('0.80')

        # 使用 helper 统一处理平台池子余额变更与流水
        self._add_pool_balance('platform_revenue_pool', platform_revenue, f"订单#{order_id} 平台收入")

        if allocs:
            for atype, ratio in allocs.items():
                if atype == 'merchant_balance':
                    continue
                alloc_amount = total_amount * ratio
                self._add_pool_balance(atype, alloc_amount, f"订单#{order_id} 分配到{atype}")
                if atype == 'public_welfare':
                    logger.debug(f"公益基金获得: ¥{alloc_amount}")
        else:
            for purpose, percent in ALLOCATIONS.items():
                if purpose == AllocationKey.PLATFORM_REVENUE_POOL:
                    continue
                alloc_amount = total_amount * percent
                self._add_pool_balance(purpose.value, alloc_amount, f"订单#{order_id} 分配到{purpose.value}")
                if purpose == AllocationKey.PUBLIC_WELFARE:
                    logger.debug(f"公益基金获得: ¥{alloc_amount}")

    def audit_and_distribute_rewards(self, reward_ids: List[int], approve: bool, auditor: str = 'admin') -> bool:
        """批量审核奖励并发放优惠券"""
        if not reward_ids:
            raise FinanceException("奖励ID列表不能为空")

        # ============= 关键修复：移除 try...except，让 FinanceException 直接抛出 =============
        # 使用核心库中的占位符构造器，避免直接拼接值到 SQL
        placeholders, params_dict = build_in_placeholders(reward_ids)
        params_tuple = tuple(params_dict[f"id{i}"] for i in range(len(reward_ids)))

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 查询待审核奖励
                cur.execute(
                    f"""SELECT id, user_id, reward_type, amount, order_id, layer
                       FROM pending_rewards 
                       WHERE id IN ({placeholders}) AND status = 'pending'""",
                    params_tuple
                )
                rewards = cur.fetchall()

                # 业务校验：未找到记录时直接抛出异常（不被捕获）
                if not rewards:
                    raise FinanceException("未找到待审核的奖励记录")

                if approve:
                    today = datetime.now().date()
                    valid_to = today + timedelta(days=COUPON_VALID_DAYS)

                    for reward in rewards:
                        # 发放优惠券
                        cur.execute(
                            """INSERT INTO coupons (user_id, coupon_type, amount, valid_from, valid_to, status)
                               VALUES (%s, 'user', %s, %s, %s, 'unused')""",
                            (reward['user_id'], reward['amount'], today, valid_to)
                        )
                        coupon_id = cur.lastrowid

                        # 更新奖励状态
                        cur.execute(
                            "UPDATE pending_rewards SET status = 'approved' WHERE id = %s",
                            (reward['id'],)
                        )

                        # 记录流水
                        reward_desc = '推荐' if reward['reward_type'] == 'referral' else f"团队L{reward['layer']}"
                        self._record_flow(
                            account_type='coupon',
                            related_user=reward['user_id'],
                            change_amount=Decimal('0'),
                            flow_type='coupon',
                            remark=f"{reward_desc}奖励发放优惠券#{coupon_id} ¥{reward['amount']:.2f}"
                        )
                        logger.debug(f"奖励{reward['id']}已批准，发放优惠券{coupon_id}")
                else:
                    # 拒绝奖励
                    cur.execute(
                        f"UPDATE pending_rewards SET status = 'rejected' WHERE id IN ({placeholders})",
                        reward_ids
                    )
                    logger.debug(f"已拒绝 {len(reward_ids)} 条奖励")

                # 提交事务
                conn.commit()
                return True

        # 移除 try...except 块，让 FinanceException 直接向上抛出

    def get_rewards_by_status(self, status: str = 'approved', reward_type: Optional[str] = None, limit: int = 50) -> \
    List[Dict[str, Any]]:
        """
        查询已自动发放的奖励记录（从 account_flow 查询）
        status 参数现在仅用于过滤：'approved'=已发放, 'all'=全部
        """
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建查询条件
                where_conditions = [
                    "af.flow_type = 'income' AND af.account_type IN ('referral_points', 'team_reward_points')"]
                params = []

                if reward_type:
                    where_conditions.append("af.account_type = %s")
                    params.append(f"{reward_type}_points")

                if status != 'all':
                    # 'approved' 表示已发放（account_flow 中已存在记录）
                    where_conditions.append("af.created_at IS NOT NULL")  # 总是已发放

                where_sql = " AND ".join(where_conditions)

                # 查询奖励流水
                cur.execute(f"""
                    SELECT af.id, af.related_user as user_id, u.name as user_name,
                           af.account_type, af.change_amount as points_issued,
                           af.remark, af.created_at
                    FROM account_flow af
                    JOIN users u ON af.related_user = u.id
                    WHERE {where_sql}
                    ORDER BY af.created_at DESC
                    LIMIT %s
                """, tuple(params + [limit]))

                rewards = cur.fetchall()

                # 转换格式
                result = []
                for r in rewards:
                    reward_type = 'referral' if 'referral' in r['account_type'] else 'team'
                    result.append({
                        "reward_id": r['id'],
                        "user_id": r['user_id'],
                        "user_name": r['user_name'],
                        "reward_type": reward_type,
                        "points_issued": float(r['points_issued']),
                        "current_status": "已自动发放",
                        "remark": r['remark'],
                        "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                        "points_field": r['account_type']
                    })

                return result

    def _get_adjusted_points_value(self) -> Optional[Dict[str, Any]]:
        """获取手动调整的积分值配置，返回包含 value 和 auto_clear 的字典"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT config_params FROM finance_accounts WHERE account_type = 'subsidy_pool'"
                    )
                    row = cur.fetchone()

                    if row and row.get('config_params'):
                        try:
                            import json
                            config = json.loads(row['config_params']) if isinstance(row['config_params'], str) else row[
                                'config_params']

                            if isinstance(config, dict) and 'points_value' in config:
                                value = Decimal(str(config['points_value']))
                                auto_clear = config.get('auto_clear', False)
                                if 0 <= value <= MAX_POINTS_VALUE:
                                    return {
                                        'value': value,
                                        'auto_clear': auto_clear
                                    }
                        except:
                            pass
        except Exception as e:
            logger.error(f"获取积分值配置失败: {e}")
        return None

    def adjust_subsidy_points_value(self, points_value: Optional[float] = None, auto_clear: bool = False) -> bool:
        """
        手动调整周补贴积分值

        Args:
            points_value: 积分值（0-0.02），传入None表示取消手动调整，恢复自动计算
            auto_clear: 是否在发放一次后自动清除（默认为False，不自动清除）
        """
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    if points_value is None:
                        # 取消调整
                        cur.execute(
                            "UPDATE finance_accounts SET config_params = NULL WHERE account_type = 'subsidy_pool'"
                        )
                        logger.info("已取消周补贴积分值手动调整，恢复自动计算")
                    else:
                        # 设置调整值
                        value = Decimal(str(points_value))
                        if value < 0 or value > MAX_POINTS_VALUE:
                            raise FinanceException(f"积分值必须在0到{MAX_POINTS_VALUE}之间")

                        import json
                        config = json.dumps({"points_value": str(value), "auto_clear": auto_clear})
                        cur.execute(
                            "UPDATE finance_accounts SET config_params = %s WHERE account_type = 'subsidy_pool'",
                            (config,)
                        )

                        logger.info(f"已设置周补贴积分值手动调整: {value:.4f}，auto_clear={auto_clear}")

                    conn.commit()
            return True
        except Exception as e:
            logger.error(f"调整积分值失败: {e}")
            raise

    def get_current_points_value(self) -> Dict[str, Any]:
        """查询当前积分值配置"""
        # 检查是否有手动调整
        adjusted_config = self._get_adjusted_points_value()

        # 获取补贴池余额和总积分
        pool_balance = self.get_account_balance('subsidy_pool')

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT SUM(COALESCE(member_points, 0)) as total FROM users")
                total_member_points = Decimal(str(cur.fetchone()['total'] or 0))

        # 自动计算值
        auto_value = pool_balance / total_member_points if total_member_points > 0 else Decimal('0')
        if auto_value > MAX_POINTS_VALUE:
            auto_value = MAX_POINTS_VALUE

        if adjusted_config:
            current_value = adjusted_config['value']
            is_manual_adjusted = True
            manual_value = float(adjusted_config['value'])
            auto_clear = adjusted_config.get('auto_clear', False)
        else:
            current_value = auto_value
            is_manual_adjusted = False
            manual_value = None
            auto_clear = False

        return {
            "current_value": float(current_value),
            "is_manual_adjusted": is_manual_adjusted,
            "manual_value": manual_value,
            "auto_clear": auto_clear,
            "auto_calculated_value": float(auto_value),
            "subsidy_pool_balance": float(pool_balance),
            "total_member_points": float(total_member_points),
            "max_allowed_value": float(MAX_POINTS_VALUE),
            "remark": "积分值 = 补贴池金额 ÷ 总积分，最高不超过0.02（2%）。如果设置了auto_clear=true，发放一次后会自动清除手动配置。"
        }

    def distribute_weekly_subsidy(self) -> bool:
        """
        发放周补贴（增加 subsidy_points 并扣减 member_points）

        关键修复：
        1. 在扣减 subsidy_pool 前检查余额是否充足
        2. 使用 _add_pool_balance 统一处理余额更新和流水记录
        3. 新增补贴池余额检查
        """
        logger.info("周补贴发放开始（发放专用点数并扣减积分）")

        pool_balance = self.get_account_balance('subsidy_pool')
        if pool_balance <= 0:
            logger.warning("❌ 补贴池余额不足")
            return False

        # 计算总积分
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT SUM(COALESCE(member_points, 0)) as total FROM users")
                total_member_points = Decimal(str(cur.fetchone()['total'] or 0))

        if total_member_points <= 0:
            logger.warning("❌ 总积分为0，无法发放补贴")
            return False

        # 检查是否有手动调整的积分值
        adjusted_config = self._get_adjusted_points_value()
        if adjusted_config:
            points_value = adjusted_config['value']
            auto_clear = adjusted_config.get('auto_clear', False)
            logger.info(f"使用手动调整的积分值: {points_value:.4f}")
        else:
            points_value = pool_balance / total_member_points
            if points_value > MAX_POINTS_VALUE:
                points_value = MAX_POINTS_VALUE
            auto_clear = False
            logger.info(f"积分价值自动计算: ¥{points_value:.4f}/分")

        logger.info(f"补贴池: ¥{pool_balance} | 总积分: {total_member_points} | 积分值: ¥{points_value:.4f}/分")

        total_distributed = Decimal('0')
        total_points_deducted = Decimal('0')
        today = datetime.now().date()

        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 查询有积分的用户
                    cur.execute(
                        "SELECT id, member_points, subsidy_points FROM users WHERE COALESCE(member_points, 0) > 0"
                    )
                    users = cur.fetchall()

                    for user in users:
                        user_id = user['id']
                        member_points = Decimal(str(user['member_points'] or 0))
                        current_subsidy_points = Decimal(str(user['subsidy_points'] or 0))

                        # 计算补贴金额 = 用户积分 × 积分价值
                        subsidy_amount = member_points * points_value

                        # 发放的点数直接等于补贴金额（1元=1点数）
                        points_to_add = subsidy_amount

                        if points_to_add <= Decimal('0'):
                            continue

                        # 只扣除与发放点数等量的积分（不再是全部积分）
                        points_to_deduct = min(points_to_add, member_points)

                        if points_to_deduct <= Decimal('0'):
                            continue

                        # ====== 发放补贴点数 ======
                        new_subsidy_points = current_subsidy_points + points_to_add
                        cur.execute(
                            "UPDATE users SET subsidy_points = %s WHERE id = %s",
                            (new_subsidy_points, user_id)
                        )
                        cur.execute(
                            "UPDATE users SET true_total_points = true_total_points + %s WHERE id = %s",
                            (points_to_add, user_id)
                        )

                        # ====== 扣减 member_points ======
                        cur.execute(
                            "UPDATE users SET member_points = member_points - %s WHERE id = %s",
                            (points_to_deduct, user_id)
                        )

                        # 获取扣减后的余额
                        cur.execute(
                            "SELECT member_points FROM users WHERE id = %s",
                            (user_id,)
                        )
                        new_balance = Decimal(str(cur.fetchone()['member_points'] or 0))

                        # 写入积分扣减流水
                        cur.execute(
                            """INSERT INTO points_log 
                               (user_id, change_amount, balance_after, type, reason, related_order, created_at)
                               VALUES (%s, %s, %s, 'member', %s, NULL, NOW())""",
                            (user_id, -points_to_deduct, new_balance, f"周补贴扣减积分")
                        )

                        # ====== 将扣除的积分转入公司积分池 ======
                        # 使用 _add_pool_balance（会自动检查余额）
                        self._add_pool_balance(
                            cur, 'company_points', points_to_deduct,
                            f"周补贴扣除积分转入 - 用户{user_id}扣除{points_to_deduct:.4f}分",
                            related_user=user_id
                        )

                        # 【关键修复】从 subsidy_pool 扣除发放的 subsidy_amount
                        # 使用 _add_pool_balance 统一处理（带余额保护）
                        try:
                            self._add_pool_balance(
                                cur, 'subsidy_pool', -subsidy_amount,
                                f"周补贴发放 - 用户{user_id}获得{points_to_add:.4f}点数",
                                related_user=None
                            )
                        except InsufficientBalanceException:
                            logger.error(f"补贴池余额不足，无法发放用户{user_id}的补贴")
                            raise FinanceException("补贴池余额不足，发放失败")

                        # 记录发放历史
                        cur.execute(
                            """INSERT INTO weekly_subsidy_records 
                               (user_id, week_start, subsidy_amount, points_before, points_deducted)
                               VALUES (%s, %s, %s, %s, %s)""",
                            (user_id, today, subsidy_amount, member_points, points_to_deduct)
                        )

                        total_distributed += subsidy_amount
                        total_points_deducted += points_to_deduct
                        logger.info(
                            f"用户{user_id}: 发放补贴点数{points_to_add:.4f}, "
                            f"扣减积分{points_to_deduct:.4f}, 余额{new_balance:.4f}, "
                            f"转入公司积分池{points_to_deduct:.4f}"
                        )

                    # 提交事务
                    conn.commit()

            # 如果设置了 auto_clear=true，发放完成后自动清除手动配置
            if auto_clear:
                logger.info("发放完成，自动清除手动积分值配置")
                self.adjust_subsidy_points_value(None)

            logger.info(f"周补贴完成: 发放¥{total_distributed:.4f}等值点数，"
                        f"扣除积分{total_points_deducted:.4f}分，涉及{len(users)}个用户")
            return True

        except InsufficientBalanceException:
            logger.error(f"❌ 周补贴发放失败: 补贴池余额不足")
            raise FinanceException("补贴池余额不足，无法完成发放")
        except Exception as e:
            logger.error(f"❌ 周补贴发放失败: {e}", exc_info=True)
            return False

    # ==================== 关键修改4：退款逻辑使用member_points ====================
    def refund_order(self, order_no: str) -> bool:
        try:
            # 先读取订单信息（只读），随后通过条件更新来避免长时间持有行锁
            result = self.session.execute(
                "SELECT order_number, status, is_member_order, user_id, total_amount, merchant_id, original_amount FROM orders WHERE order_number = %s",
                {"order_number": order_no}
            )
            order = result.fetchone()

            if not order or order.status == 'refunded':
                raise FinanceException("订单不存在或已退款")

            # 尝试将订单状态置为 refunded（条件更新保证并发安全且不会长时间锁行）
            res = self.session.execute(
                "UPDATE orders SET status = 'refunded' WHERE order_number = %s AND status != 'refunded'",
                {"order_number": order_no}
            )
            if res.rowcount == 0:
                raise FinanceException("订单已被并发处理或状态已改变")

            is_member = order.is_member_order
            user_id = order.user_id
            amount = Decimal(str(order.total_amount))
            merchant_id = order.merchant_id

            logger.debug(f"订单退款: {order_no} (会员商品: {is_member})")

            if is_member:
                result = self.session.execute(
                    "SELECT referrer_id FROM user_referrals WHERE user_id = %s",
                    {"user_id": user_id}
                )
                referrer = result.fetchone()
                if referrer and referrer.referrer_id:
                    reward_amount = Decimal(str(order.original_amount)) * Decimal('0.50')
                    self.session.execute(
                        """UPDATE users SET promotion_balance = promotion_balance - %s
                           WHERE id = %s AND promotion_balance >= %s""",
                        {"amount": reward_amount, "user_id": referrer.referrer_id}
                    )

                    # 动态构造 SELECT 语句（使用临时连接获取表结构，不影响当前事务）
                    with get_conn() as temp_conn:
                        with temp_conn.cursor() as temp_cur:
                            select_fields, existing_columns = _build_team_rewards_select(temp_cur, ['reward_amount'])
                            # 确保包含 user_id 字段（如果不存在则添加默认值 0）
                            if 'user_id' not in existing_columns:
                                select_fields = "0 AS user_id, " + select_fields
                            else:
                                # 如果 user_id 存在，确保它在最前面
                                fields_list = [f.strip() for f in select_fields.split(",")]
                                # 移除 user_id（如果存在）
                                fields_list = [f for f in fields_list if
                                               f != 'user_id' and not f.startswith('user_id ')]
                                select_fields = "user_id, " + ", ".join(fields_list)

                    result = self.session.execute(
                        f"SELECT {select_fields} FROM team_rewards WHERE order_id = %s",
                        {"order_id": order.id}
                    )
                    rewards = result.fetchall()
                    for reward in rewards:
                        self.session.execute(
                            """UPDATE users SET promotion_balance = promotion_balance - %s
                               WHERE id = %s AND promotion_balance >= %s""",
                            {"amount": reward.reward_amount, "user_id": reward.user_id}
                        )

                    # 关键修改：退款时扣减member_points（不再是points）
                    user_points = Decimal(str(order.original_amount))
                    self.session.execute(
                        "UPDATE users SET member_points = GREATEST(member_points - %s, 0) WHERE id = %s",
                        {"points": user_points, "user_id": user_id}
                    )
                    self.session.execute(
                        "UPDATE users SET member_level = GREATEST(member_level - 1, 0) WHERE id = %s",
                        {"user_id": user_id}
                    )
                    logger.info(f"⚠️ 用户{user_id}退款后降级")

                merchant_amount = amount * Decimal('0.80')

                if is_member:
                    self._check_pool_balance('platform_revenue_pool', merchant_amount)
                    # 从平台收入池扣减并记录流水
                    self._add_pool_balance('platform_revenue_pool', -merchant_amount, f"退款 - 订单#{order_no}")
                else:
                    if merchant_id == PLATFORM_MERCHANT_ID:
                        self._add_pool_balance('platform_revenue_pool', -merchant_amount, f"退款 - 订单#{order_no}")
                    else:
                        self._check_user_balance(merchant_id, merchant_amount, 'merchant_balance')
                        self.session.execute(
                            "UPDATE users SET merchant_balance = merchant_balance - %s WHERE id = %s",
                            {"amount": merchant_amount, "merchant_id": merchant_id}
                        )

                self.session.execute(
                    "UPDATE orders SET refund_status = 'refunded', updated_at = NOW() WHERE id = %s",
                    {"order_id": order.id}
                )

            logger.debug(f"订单退款成功: {order_no}")
            return True

        except Exception as e:
            logger.error(f"❌ 退款失败: {e}")
            return False

    def apply_withdrawal(self, user_id: int, amount: float, withdrawal_type: str = 'user') -> Optional[int]:
        """申请提现"""
        try:
            balance_field = 'promotion_balance' if withdrawal_type == 'user' else 'merchant_balance'
            amount_decimal = Decimal(str(amount))

            self._check_user_balance(user_id, amount_decimal, balance_field)

            tax_amount = amount_decimal * TAX_RATE
            actual_amount = amount_decimal - tax_amount

            status = 'pending_manual' if amount_decimal > 5000 else 'pending_auto'

            result = self.session.execute(
                """INSERT INTO withdrawals (user_id, amount, tax_amount, actual_amount, status)
                   VALUES (%s, %s, %s, %s, %s)""",
                {
                    "user_id": user_id,
                    "amount": amount_decimal,
                    "tax_amount": tax_amount,
                    "actual_amount": actual_amount,
                    "status": status
                }
            )
            withdrawal_id = result.lastrowid

            self.session.execute(
                f"UPDATE users SET {_quote_identifier(balance_field)} = {_quote_identifier(balance_field)} - :amount WHERE id = :user_id",
                {"amount": amount_decimal, "user_id": user_id}
            )

            self._record_flow(
                account_type=balance_field,
                related_user=user_id,
                change_amount=-amount_decimal,
                flow_type='expense',
                remark=f"{withdrawal_type}_提现申请冻结 #{withdrawal_id}"
            )

            self.session.execute(
                "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'company_balance'",
                {"amount": tax_amount}
            )

            self._record_flow(
                account_type='company_balance',
                related_user=user_id,
                change_amount=tax_amount,
                flow_type='income',
                remark=f"{withdrawal_type}_提现个税 #{withdrawal_id}"
            )

            self.session.commit()
            logger.debug(f"提现申请 #{withdrawal_id}: ¥{amount_decimal}（税¥{tax_amount:.2f}，实到¥{actual_amount:.2f}）")
            return withdrawal_id

        except Exception as e:
            self.session.rollback()
            logger.error(f"❌ 提现申请失败: {e}")
            return None

    def audit_withdrawal(self, withdrawal_id: int, approve: bool, auditor: str = 'admin') -> bool:
        """审核提现申请"""
        # ============= 关键修复：移除 try...except，让 FinanceException 直接抛出 =============

        # 查询表结构（只读操作，无需事务）
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SHOW COLUMNS FROM withdrawals")
                columns = cur.fetchall()

        # 执行审核（需要事务）
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 动态构造SELECT语句并锁定行
                asset_keywords = ['balance', 'points', 'amount', 'total', 'frozen', 'available', 'tax']
                select_fields = []

                for col in columns:
                    field_name = col['Field']
                    field_type = col['Type'].upper()
                    is_asset_field = any(keyword in field_name.lower() for keyword in asset_keywords)
                    is_numeric_type = 'DECIMAL' in field_type or 'INT' in field_type

                    if is_asset_field and is_numeric_type:
                        select_fields.append(f"COALESCE(`{field_name}`, 0) AS `{field_name}`")
                    else:
                        select_fields.append(f"`{field_name}`")

                # 使用条件更新避免长时间锁定行：先尝试原子性更新状态
                new_status = 'approved' if approve else 'rejected'
                cur.execute(
                    """UPDATE withdrawals SET status = %s, audit_remark = %s, processed_at = NOW()
                       WHERE id = %s AND status IN ('pending_auto','pending_manual')""",
                    (new_status, f"{auditor}审核", withdrawal_id)
                )

                if cur.rowcount == 0:
                    raise FinanceException("提现记录不存在或已处理")

                # 读取记录以便后续处理（短查询）
                cur.execute(f"SELECT {build_select_list(select_fields)} FROM withdrawals WHERE id = %s", (withdrawal_id,))
                withdraw = cur.fetchone()

                if approve:
                    self._record_flow(
                        account_type='withdrawal',
                        related_user=withdraw['user_id'],
                        change_amount=Decimal(str(withdraw['actual_amount'])),
                        flow_type='income',
                        remark=f"提现到账 #{withdrawal_id}"
                    )
                    logger.debug(f"提现审核通过 #{withdrawal_id}，到账¥{withdraw['actual_amount']:.2f}")
                else:
                    # 退回金额
                    balance_field = 'promotion_balance' if withdraw.get('withdrawal_type',
                                                                        'user') == 'user' else 'merchant_balance'
                    cur.execute(
                        f"UPDATE users SET `{balance_field}` = COALESCE(`{balance_field}`, 0) + %s WHERE id = %s",
                        (withdraw['amount'], withdraw['user_id'])
                    )

                    self._record_flow(
                        account_type=balance_field,
                        related_user=withdraw['user_id'],
                        change_amount=Decimal(str(withdraw['amount'])),
                        flow_type='income',
                        remark=f"提现拒绝退回 #{withdrawal_id}"
                    )
                    logger.debug(f"提现审核拒绝 #{withdrawal_id}")

                # 提交事务
                conn.commit()
                return True

        # 移除 try...except 块，让 FinanceException 直接向上抛出

    def _record_flow(self, account_type: str, related_user: Optional[int],
                     change_amount: Decimal, flow_type: str,
                     remark: str, account_id: Optional[int] = None) -> None:
        # 兼容封装：使用内部统一的 account_flow 插入函数
        self._insert_account_flow(account_type=account_type,
                                  related_user=related_user,
                                  change_amount=change_amount,
                                  flow_type=flow_type,
                                  remark=remark,
                                  account_id=account_id)

    def _insert_account_flow(self, cur, account_type: str, related_user: Optional[int],
                             change_amount: Decimal, flow_type: str,
                             remark: str, account_id: Optional[int] = None) -> None:
        """插入流水记录（必须使用同一个cur）"""
        # 修复：移除多余的 cur 参数，直接从 cur 查询余额
        if related_user and account_type in ['promotion_balance', 'merchant_balance']:
            # 查询用户余额字段
            select_sql = build_dynamic_select(
                cur,
                "users",
                where_clause="id=%s",
                select_fields=[account_type]
            )
            cur.execute(select_sql, (related_user,))
            row = cur.fetchone()
            balance_after = Decimal(str(row.get(account_type, 0) or 0)) if row else Decimal('0')
        else:
            # 查询平台资金池余额
            cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", (account_type,))
            row = cur.fetchone()
            balance_after = Decimal(str(row['balance'] if row and row['balance'] is not None else 0))

        cur.execute(
            """INSERT INTO account_flow (account_id, account_type, related_user, change_amount, balance_after, flow_type, remark, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())""",
            (account_id, account_type, related_user, change_amount, balance_after, flow_type, remark)
        )

    def _add_pool_balance(self, cur, account_type: str, amount: Decimal, remark: str,
                          related_user: Optional[int] = None) -> Decimal:
        # 如果是扣减操作，先检查余额
        if amount < 0:
            self._ensure_pool_balance(account_type, abs(amount))

        # 执行余额更新（使用原子操作）
        cur.execute(
            "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
            (amount, account_type)
        )

        # 获取更新后的余额
        cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", (account_type,))
        row = cur.fetchone()
        balance_after = Decimal(str(row['balance'] if row and row['balance'] is not None else 0))

        # 记录流水
        flow_type = 'income' if amount >= 0 else 'expense'
        self._insert_account_flow(cur, account_type=account_type, related_user=related_user,
                                  change_amount=amount, flow_type=flow_type, remark=remark)

        logger.debug(f"资金池 {account_type} 余额变更: {amount:.4f}，当前余额: {balance_after:.4f}")
        return balance_after

    # 关键修改：points_log插入支持DECIMAL(12,4)精度
    def _insert_points_log(self, user_id: int, change_amount: Decimal, balance_after: Decimal, type: str, reason: str,
                           related_order: Optional[int] = None) -> None:
        """插入 `points_log` 记录。change_amount 和 balance_after 使用 Decimal 类型，支持小数点后4位精度。"""
        self.session.execute(
            """INSERT INTO points_log (user_id, change_amount, balance_after, type, reason, related_order, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
            {
                "user_id": user_id,
                "change": change_amount,
                "balance": balance_after,
                "type": type,
                "reason": reason,
                "related_order": related_order
            }
        )

    # 关键修改：使用COALESCE处理DECIMAL字段
    def _update_user_balance(self, user_id: int, field: str, delta: Decimal) -> Decimal:
        """对 `users` 表的指定余额字段做增减，并返回更新后的值。
        注意：`field` 必须是受信任的字段名（由调用处保证）。"""
        # 安全地引用字段名并使用命名参数执行更新
        from core.table_access import _quote_identifier

        quoted_field = _quote_identifier(field)
        self.session.execute(
            f"UPDATE users SET {quoted_field} = COALESCE({quoted_field}, 0) + :delta WHERE id = :user_id",
            {"delta": delta, "user_id": user_id}
        )
        # 使用动态表访问获取更新后的值
        with get_conn() as conn:
            with conn.cursor() as cur:
                select_sql = build_dynamic_select(
                    cur,
                    "users",
                    where_clause="id=%s",
                    select_fields=[field]
                )
                cur.execute(select_sql, (user_id,))
                row = cur.fetchone()
                return Decimal(str(row.get(field, 0) or 0)) if row else Decimal('0')

    def _get_balance_after(self, account_type: str, related_user: Optional[int] = None) -> Decimal:
        if related_user and account_type in ['promotion_balance', 'merchant_balance']:
            field = account_type
            # 使用动态表访问获取余额
            with get_conn() as conn:
                with conn.cursor() as cur:
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="id=%s",
                        select_fields=[field]
                    )
                    cur.execute(select_sql, (related_user,))
                    row = cur.fetchone()
                    return Decimal(str(row.get(field, 0) or 0)) if row else Decimal('0')
        else:
            return self.get_account_balance(account_type)

    # 在 get_public_welfare_balance 方法中添加
    def get_public_welfare_balance(self) -> Decimal:
        # ========== 临时日志开始 ==========
        logger.info("🔍 DEBUG: get_public_welfare_balance 被调用")
        result = self.get_account_balance('public_welfare')
        logger.info(f"🔍 DEBUG: get_account_balance 返回: {result} (类型: {type(result)})")
        return result
        # ========== 临时日志结束 ==========
        # return self.get_account_balance('public_welfare')

    # ==================== 可配置资金池分配（新增） ====================
    def get_pool_allocations(self) -> Dict[str, Decimal]:
        """
        获取当前资金池分配配置。

        返回字典：
        - merchant_balance: Decimal (如 0.80)
        - 子池键: Decimal（占比，相对于总订单金额，如 0.01 表示 1%）
        如果数据库中没有配置，返回默认值（与项目原始占比一致）。
        """
        # 我们按行读取 finance_accounts 中每个子池的 config_params.allocation
        account_keys = [
            'merchant_balance', 'public_welfare', 'maintain_pool', 'subsidy_pool',
            'director_pool', 'shop_pool', 'city_pool', 'branch_pool', 'fund_pool'
        ]
        cfg_map: Dict[str, Any] = {}
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 确保表有 config_params 列；如果没有则尝试添加（容错）
                try:
                    cur.execute("SHOW COLUMNS FROM finance_accounts LIKE 'config_params'")
                    if not cur.fetchone():
                        try:
                            cur.execute("ALTER TABLE finance_accounts ADD COLUMN config_params JSON DEFAULT NULL")
                            conn.commit()
                        except Exception as e:
                            logger.debug(f"无法添加 config_params 列: {e}")

                except Exception:
                    logger.debug("检查 finance_accounts.config_params 列时出错，继续尝试读取行")

                # 查询表中与我们关心的 account_type 列表匹配的行（使用安全占位符构造）
                try:
                    placeholders, params_dict = build_in_placeholders(account_keys)
                    params_tuple = tuple(params_dict[f"id{i}"] for i in range(len(account_keys)))
                    cur.execute(f"SELECT account_type, config_params FROM finance_accounts WHERE account_type IN ({placeholders})", params_tuple)
                    rows = cur.fetchall()
                except Exception as e:
                    logger.error(f"读取 finance_accounts 行失败: {e}")
                    rows = []

                for r in rows:
                    at = r.get('account_type')
                    cp = r.get('config_params')
                    if not cp:
                        continue
                    try:
                        if isinstance(cp, str):
                            parsed = json.loads(cp)
                        else:
                            parsed = cp
                        # 支持两种存储形态：{"allocation":"0.01"} 或 直接为字符串数值
                        if isinstance(parsed, dict) and 'allocation' in parsed:
                            cfg_map[at] = Decimal(str(parsed['allocation']))
                        else:
                            # 可能以前误存为单行 allocations_config map
                            # parsed 可能是 {'city_pool':'0.01',...}
                            if isinstance(parsed, dict) and at in parsed:
                                cfg_map[at] = Decimal(str(parsed[at]))
                    except Exception:
                        logger.debug(f"解析 finance_accounts.account_type={at} config_params 失败，忽略")

        # 默认配置（数值为相对于总额的占比）
        defaults = {
            'merchant_balance': Decimal('0.80'),
            'public_welfare': Decimal('0.01'),
            'maintain_pool': Decimal('0.01'),
            'subsidy_pool': Decimal('0.12'),
            'director_pool': Decimal('0.02'),
            'shop_pool': Decimal('0.01'),
            'city_pool': Decimal('0.01'),
            'branch_pool': Decimal('0.005'),
            'fund_pool': Decimal('0.015')
        }

        # 用读取到的行优先覆盖默认值
        result: Dict[str, Decimal] = defaults.copy()
        for k in defaults.keys():
            if k in cfg_map:
                result[k] = cfg_map[k]

        return result

    def _validate_allocations(self, allocs: Dict[str, Any]) -> Dict[str, Decimal]:
        """校验并规范化传入的 allocations 字典，返回 Decimal 值字典。"""
        allowed_subpools = {
            'public_welfare', 'maintain_pool', 'subsidy_pool', 'director_pool',
            'shop_pool', 'city_pool', 'branch_pool', 'fund_pool'
        }
        # merchant_balance 可选，但我们不允许设置超过 1
        out: Dict[str, Decimal] = {}
        for k, v in allocs.items():
            if k not in allowed_subpools and k != 'merchant_balance':
                raise ValueError(f"未知的资金池键: {k}")
            try:
                dec = Decimal(str(v))
            except Exception:
                raise ValueError(f"资金池比例必须是数值: {k}")
            if dec < 0 or dec > 1:
                raise ValueError(f"资金池比例范围必须在 0..1 之间: {k}")
            out[k] = dec

        # 校验总和：所有子池之和（不包括 merchant_balance）不得超过 0.20
        sub_sum = sum((out.get(k, Decimal('0')) for k in allowed_subpools), Decimal('0'))
        if sub_sum > Decimal('0.20'):
            raise ValueError("所有子资金池的占比之和不得超过20%（0.20）")

        # 若提供 merchant_balance，则确保 merchant_balance + sub_sum <=1
        if 'merchant_balance' in out:
            if out['merchant_balance'] + sub_sum > Decimal('1'):
                raise ValueError("merchant_balance 与子池之和不得超过 100%")

        return out

    def set_pool_allocations(self, allocations: Dict[str, Any]) -> Dict[str, Decimal]:
        """
        设置/更新资金池分配配置，按 `account_type` 将 allocation 写入对应的 `finance_accounts.config_params` 字段。

        校验规则：所有子资金池（非 merchant_balance）的占比和不得超过 0.20（即 20%）。
        返回保存后的配置（Decimal 值）。
        """
        normalized = self._validate_allocations(allocations)

        # 将每个 allocation 写入对应的 finance_accounts 行的 config_params 字段
        with get_conn() as conn:
            with conn.cursor() as cur:
                for atype, dec in normalized.items():
                    try:
                        cur.execute("SELECT id, config_params FROM finance_accounts WHERE account_type=%s LIMIT 1", (atype,))
                        row = cur.fetchone()
                        new_cp = None
                        if row:
                            cp = row.get('config_params')
                            try:
                                if isinstance(cp, str):
                                    parsed = json.loads(cp)
                                else:
                                    parsed = cp or {}
                            except Exception:
                                parsed = {}
                            if not isinstance(parsed, dict):
                                parsed = {}
                            parsed['allocation'] = str(dec)
                            new_cp = json.dumps(parsed, ensure_ascii=False)
                            cur.execute("UPDATE finance_accounts SET config_params=%s WHERE id=%s", (new_cp, row['id']))
                        else:
                            # account_type 不存在则插入新行
                            parsed = {'allocation': str(dec)}
                            cur.execute(
                                "INSERT INTO finance_accounts(account_name, account_type, balance, config_params) VALUES (%s,%s,%s,%s)",
                                (atype, atype, 0, json.dumps(parsed, ensure_ascii=False))
                            )
                    except Exception as e:
                        logger.error(f"更新 finance_accounts.account_type={atype} 的 config_params 失败: {e}")
                conn.commit()

        # 返回最新的合并配置（读取每行）
        return self.get_pool_allocations()

    def get_public_welfare_flow(self, limit: int = 50) -> List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT id, related_user, change_amount, balance_after, flow_type, remark, created_at
                       FROM account_flow WHERE account_type = %s
                       ORDER BY created_at DESC LIMIT %s""",
                    ("public_welfare", limit)
                )
                flows = cur.fetchall()
                return [{
                    "id": f['id'],
                    "related_user": f['related_user'],
                    "change_amount": float(f['change_amount']),
                    "balance_after": float(f['balance_after']) if f['balance_after'] else None,
                    "flow_type": f['flow_type'],
                    "remark": f['remark'],
                    "created_at": f['created_at'].strftime("%Y-%m-%d %H:%M:%S")
                } for f in flows]

    def get_public_welfare_report(self, start_date: str, end_date: str) -> Dict[str, Any]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 汇总查询
                cur.execute(
                    """SELECT COUNT(*) as total_transactions,
                              SUM(CASE WHEN flow_type = 'income' THEN change_amount ELSE 0 END) as total_income,
                              SUM(CASE WHEN flow_type = 'expense' THEN change_amount ELSE 0 END) as total_expense
                       FROM account_flow WHERE account_type = 'public_welfare'
                       AND DATE(created_at) BETWEEN %s AND %s""",
                    (start_date, end_date)
                )
                summary = cur.fetchone()

                # 明细查询
                cur.execute(
                    """SELECT id, related_user, change_amount, balance_after, flow_type, remark, created_at
                       FROM account_flow WHERE account_type = 'public_welfare'
                       AND DATE(created_at) BETWEEN %s AND %s
                       ORDER BY created_at DESC""",
                    (start_date, end_date)
                )
                details = cur.fetchall()

                return {
                    "summary": {
                        "total_transactions": summary['total_transactions'] or 0,
                        "total_income": float(summary['total_income'] or 0),
                        "total_expense": float(summary['total_expense'] or 0),
                        "net_balance": float((summary['total_income'] or 0) - (summary['total_expense'] or 0))
                    },
                    "details": [{
                        "id": d['id'],
                        "related_user": d['related_user'],
                        "change_amount": float(d['change_amount']),
                        "balance_after": float(d['balance_after']) if d['balance_after'] else None,
                        "flow_type": d['flow_type'],
                        "remark": d['remark'],
                        "created_at": d['created_at'].strftime("%Y-%m-%d %H:%M:%S")
                    } for d in details]
                }

    def set_referrer(self, user_id: int, referrer_id: int) -> bool:
        try:
            # 使用动态表访问获取推荐人等级
            with get_conn() as conn:
                with conn.cursor() as cur:
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="id=%s",
                        select_fields=["member_level"]
                    )
                    cur.execute(select_sql, (referrer_id,))
                    row = cur.fetchone()
                    referrer = type('obj', (object,),
                                    {'member_level': row.get('member_level', 0) or 0 if row else 0})() if row else None
            if not referrer:
                raise FinanceException(f"推荐人不存在: {referrer_id}")

            if user_id == referrer_id:
                raise FinanceException("不能设置自己为推荐人")

            result = self.session.execute(
                "SELECT referrer_id FROM user_referrals WHERE user_id = %s",
                {"user_id": user_id}
            )
            if result.fetchone():
                raise FinanceException("用户已存在推荐人，无法重复设置")

            self.session.execute(
                "INSERT INTO user_referrals (user_id, referrer_id) VALUES (%s, %s)",
                {"user_id": user_id, "referrer_id": referrer_id}
            )

            self.session.commit()
            logger.debug(f"用户{user_id}的推荐人设置为{referrer_id}（{referrer.member_level}星）")
            return True

        except Exception as e:
            self.session.rollback()
            logger.error(f"❌ 设置推荐人失败: {e}")
            return False

    def get_user_referrer(self, user_id: int) -> Optional[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT ur.referrer_id, u.name, u.member_level
                       FROM user_referrals ur JOIN users u ON ur.referrer_id = u.id
                       WHERE ur.user_id = %s""",
                    (user_id,)
                )
                row = cur.fetchone()
                return {
                    "referrer_id": row['referrer_id'],
                    "name": row['name'],
                    "member_level": row['member_level']
                } if row else None

    def get_user_team(self, user_id: int, max_layer: int = MAX_TEAM_LAYER) -> List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """WITH RECURSIVE team_tree AS (
                       SELECT user_id, referrer_id, 1 as layer FROM user_referrals WHERE referrer_id = %s
                       UNION ALL
                       SELECT ur.user_id, ur.referrer_id, tt.layer + 1
                       FROM user_referrals ur JOIN team_tree tt ON ur.referrer_id = tt.user_id
                       WHERE tt.layer < %s
                       )
                       SELECT tt.user_id, u.name, u.member_level, tt.layer
                       FROM team_tree tt JOIN users u ON tt.user_id = u.id
                       ORDER BY tt.layer, tt.user_id""",
                    (user_id, max_layer)
                )
                results = cur.fetchall()
                return [{
                    "user_id": r['user_id'],
                    "name": r['name'],
                    "member_level": r['member_level'],
                    "layer": r['layer']
                } for r in results]

    def check_director_promotion(self) -> bool:
        try:
            logger.debug("荣誉董事晋升审核")

            result = self.session.execute("SELECT id FROM users WHERE member_level = 6")
            six_star_users = result.fetchall()

            promoted_count = 0
            for user in six_star_users:
                user_id = user.id

                result = self.session.execute(
                    """SELECT COUNT(DISTINCT u.id) as count
                       FROM user_referrals ur JOIN users u ON ur.user_id = u.id
                       WHERE ur.referrer_id = %s AND u.member_level = 6""",
                    {"user_id": user_id}
                )
                direct_count = result.fetchone().count

                result = self.session.execute(
                    """WITH RECURSIVE team AS (
                       SELECT user_id, referrer_id, 1 as level FROM user_referrals WHERE referrer_id = %s
                       UNION ALL
                       SELECT ur.user_id, ur.referrer_id, t.level + 1
                       FROM user_referrals ur JOIN team t ON ur.referrer_id = t.user_id
                       WHERE t.level < 6
                       )
                       SELECT COUNT(DISTINCT t.user_id) as count
                       FROM team t JOIN users u ON t.user_id = u.id
                       WHERE u.member_level = 6""",
                    {"user_id": user_id}
                )
                total_count = result.fetchone().count

                if direct_count >= 3 and total_count >= 10:
                    result = self.session.execute(
                        "UPDATE users SET status = 9 WHERE id = %s AND status != 9",
                        {"user_id": user_id}
                    )
                    if result.rowcount > 0:
                        promoted_count += 1
                        logger.info(f"用户{user_id}晋升为荣誉董事！（直接:{direct_count}, 团队:{total_count}）")

            self.session.commit()
            logger.info(f"荣誉董事审核完成: 晋升{promoted_count}人")
            return True

        except Exception as e:
            self.session.rollback()
            logger.error(f"❌ 荣誉董事审核失败: {e}")
            return False

    # ==================== 关键修改6：get_user_info使用member_points ====================
    def get_user_info(self, user_id: int) -> Dict[str, Any]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 用户主信息
                # 关键修改：查询member_points而非points
                cur.execute(
                    """SELECT id, mobile, name, member_level, member_points, promotion_balance,
                       merchant_points, merchant_balance, status
                       FROM users WHERE id = %s""",
                    (user_id,)
                )
                user = cur.fetchone()
                if not user:
                    raise FinanceException("用户不存在")

                # 优惠券统计
                cur.execute(
                    """SELECT COUNT(*) as count, SUM(amount) as total_amount
                       FROM coupons WHERE user_id = %s AND status = 'unused'""",
                    (user_id,)
                )
                coupons = cur.fetchone()

                # 角色判定
                roles = []
                # 关键修改：使用member_points判断用户角色
                if user['member_points'] > 0 or user['promotion_balance'] > 0:
                    roles.append("普通用户")
                if user['merchant_points'] > 0 or user['merchant_balance'] > 0:
                    roles.append("商家")

                star_level = "荣誉董事" if user['status'] == 9 else (
                    f"{user['member_level']}星级会员" if user['member_level'] > 0 else "非会员")

                return {
                    "id": user['id'],
                    "mobile": user['mobile'],
                    "name": user['name'],
                    "member_level": user['member_level'],
                    "member_points": user['member_points'],  # 修改：返回member_points
                    "promotion_balance": float(user['promotion_balance']),
                    "merchant_points": user['merchant_points'],
                    "merchant_balance": float(user['merchant_balance']),
                    "roles": roles,
                    "star_level": star_level,
                    "status": user['status'],
                    "coupons": {
                        "unused_count": coupons['count'] or 0,
                        "total_amount": float(coupons['total_amount'] or 0)
                    }
                }

    def get_user_coupons(self, user_id: int, status: str = 'unused') -> List[Dict[str, Any]]:
        """查询用户优惠券列表，包含使用范围限制信息"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT id, coupon_type, amount, applicable_product_type, status, valid_from, valid_to, used_at, created_at
                       FROM coupons WHERE user_id = %s AND status = %s
                       ORDER BY created_at DESC""",
                    (user_id, status)
                )
                coupons = cur.fetchall()
                return [{
                    "id": c['id'],
                    "coupon_type": c['coupon_type'],
                    "amount": float(c['amount']),
                    "applicable_product_type": c['applicable_product_type'],  # 新增
                    "applicable_product_type_text": {  # 友好显示
                        'all': '不限制',
                        'normal_only': '仅普通商品',
                        'member_only': '仅会员商品'
                    }.get(c['applicable_product_type'], '未知'),
                    "status": c['status'],
                    "valid_from": c['valid_from'].strftime("%Y-%m-%d"),
                    "valid_to": c['valid_to'].strftime("%Y-%m-%d"),
                    "used_at": c['used_at'].strftime("%Y-%m-%d %H:%M:%S") if c['used_at'] else None,
                    "created_at": c['created_at'].strftime("%Y-%m-%d %H:%M:%S")
                } for c in coupons]
            # ----------------------------------
                # 供线下模块调用的快捷接口
            # ----------------------------------
    def list_available(self, user_id: int, amount: int = 0) -> List[Dict[str, Any]]:
        """
        查询用户当前可用的优惠券列表（线下收银台用）
        :param user_id: 用户ID
        :param amount: 订单金额（分），用于过滤门槛
        :return: 优惠券列表，元素格式同 get_user_coupons
        """
        return self.get_user_coupons(user_id, status='unused')

    # ==================== 关键修改7：财务报告使用member_points ====================
    def get_finance_report(self) -> Dict[str, Any]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 用户资产
                # 关键修改：SUM(member_points)替代SUM(points)
                cur.execute("SELECT SUM(member_points) as points, SUM(promotion_balance) as balance FROM users")
                user = cur.fetchone()

                # 商家资产
                cur.execute("""SELECT SUM(merchant_points) as points, SUM(merchant_balance) as balance
                              FROM users WHERE merchant_points > 0 OR merchant_balance > 0""")
                merchant = cur.fetchone()

                # 平台资金池 - 动态构造查询，对资产字段做降级默认值
                # 先获取表结构
                cur.execute("SHOW COLUMNS FROM finance_accounts")
                columns = cur.fetchall()

                # 识别资产字段关键词（数值类型字段）
                asset_keywords = ['balance', 'points', 'amount', 'total', 'frozen', 'available']
                from core.table_access import _quote_identifier

                select_fields = []
                for col in columns:
                    field_name = col['Field']
                    field_type = col['Type'].upper()
                    # 如果是资产相关字段（字段名包含资产关键词）且为数值类型，添加降级默认值
                    is_asset_field = any(keyword in field_name.lower() for keyword in asset_keywords)
                    is_numeric_type = 'DECIMAL' in field_type or 'INT' in field_type or 'FLOAT' in field_type or 'DOUBLE' in field_type

                    if is_asset_field and is_numeric_type:
                        select_fields.append(f"COALESCE({_quote_identifier(field_name)}, 0) AS {_quote_identifier(field_name)}")
                    else:
                        select_fields.append(_quote_identifier(field_name))

                # 动态构造 SELECT 语句
                select_sql = f"SELECT {build_select_list(select_fields)} FROM {_quote_identifier('finance_accounts')}"
                cur.execute(select_sql)
                pools = cur.fetchall()

                # 优惠券统计
                cur.execute("""SELECT COUNT(*) as count, SUM(amount) as total_amount
                              FROM coupons WHERE status = 'unused'""")
                coupons = cur.fetchone()

                public_welfare_balance = self.get_public_welfare_balance()

                platform_pools = []
                for pool in pools:
                    if pool['balance'] > 0:
                        balance = int(pool['balance']) if 'points' in pool['account_type'] else float(pool['balance'])
                        platform_pools.append({
                            "name": pool['account_name'],
                            "type": pool['account_type'],
                            "balance": balance
                        })

                return {
                    "user_assets": {
                        # 关键修改：返回member_points
                        "total_member_points": float(user['points'] or 0),  # 修改：明确member_points
                        "total_points": float(user['points'] or 0),  # 兼容旧接口
                        "total_balance": float(user['balance'] or 0)
                    },
                    "merchant_assets": {
                        "total_merchant_points": float(merchant['points'] or 0),
                        "total_balance": float(merchant['balance'] or 0)
                    },
                    "platform_pools": platform_pools,
                    "public_welfare_fund": {
                        "account_name": "公益基金",
                        "account_type": "public_welfare",
                        "balance": float(public_welfare_balance),
                        "reserved": 0.0,
                        "remark": "该账户自动汇入1%交易额"
                    },
                    "coupons_summary": {
                        "unused_count": coupons['count'] or 0,
                        "total_amount": float(coupons['total_amount'] or 0),
                        "remark": "周补贴改为发放点数"
                    }
                }

    def get_account_flow_report(self, limit: int = 50) -> List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 获取表结构
                cur.execute("SHOW COLUMNS FROM account_flow")
                columns = cur.fetchall()

                # 识别资产字段（DECIMAL 类型字段）
                asset_fields = set()
                all_fields = []
                for col in columns:
                    field_name = col['Field']
                    field_type = col['Type'].upper()
                    all_fields.append(field_name)
                    # 判断是否为资产字段（DECIMAL 类型）
                    if 'DECIMAL' in field_type or 'FLOAT' in field_type or 'DOUBLE' in field_type:
                        asset_fields.add(field_name)

                # 动态构造 SELECT 语句，对资产字段做降级默认值处理
                from core.table_access import _quote_identifier
                select_parts = []
                for field in all_fields:
                    if field in asset_fields:
                        select_parts.append(f"COALESCE({_quote_identifier(field)}, 0) AS {_quote_identifier(field)}")
                    else:
                        select_parts.append(_quote_identifier(field))

                sql = f"SELECT {build_select_list(select_parts)} FROM {_quote_identifier('account_flow')} ORDER BY created_at DESC LIMIT %s"
                cur.execute(sql, (limit,))
                flows = cur.fetchall()

                # 格式化返回结果
                result = []
                for f in flows:
                    item = {}
                    for field in all_fields:
                        value = f[field]
                        if field in asset_fields:
                            # 资产字段转换为 float
                            item[field] = float(value) if value is not None else 0.0
                        elif field == 'created_at' and value:
                            # 日期字段格式化
                            if isinstance(value, datetime):
                                item[field] = value.strftime("%Y-%m-%d %H:%M:%S")
                            else:
                                item[field] = str(value)
                        else:
                            item[field] = value
                    result.append(item)

                return result

    # ========== 完整函数 1：获取手动调整配置（辅助函数） ==========
    def _get_adjusted_unilevel_amount(self) -> Optional[Decimal]:
        """获取手动调整的联创分红金额配置"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT config_params FROM finance_accounts WHERE account_type = 'honor_director'"
                    )
                    row = cur.fetchone()

                    if row and row.get('config_params'):
                        try:
                            import json
                            config = json.loads(row['config_params'])
                            if 'fixed_amount_per_weight' in config:
                                return Decimal(str(config['fixed_amount_per_weight']))
                        except (json.JSONDecodeError, KeyError, TypeError):
                            pass
        except Exception as e:
            logger.error(f"获取调整配置失败: {e}")
        return None

    # ========== 完整函数 2：计算联创星级分红预览 ==========
    def calculate_unilevel_dividend_preview(self) -> Dict[str, Any]:
        """
        计算联创星级分红预览（展示每个权重的金额 + 用户上限1万）

        返回：
        - 资金池余额
        - 总权重
        - 每个权重的自动计算金额
        - 是否设置了手动调整
        - 所有联创用户列表（包含理论金额和实际金额）
        - total_capped_users: 达到上限的用户数（新增）
        - capped_users_list: 被限制的用户列表（新增）
        """
        logger.info("计算联创星级分红预览（含单个用户上限1万）")

        # 1. 查询分红池余额
        pool_balance = self.get_account_balance('honor_director')

        # 2. 查询所有联创用户
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SET time_zone = '+08:00'")

                cur.execute("""
                    SELECT uu.user_id, uu.level, u.name, u.member_level
                    FROM user_unilevel uu
                    JOIN users u ON uu.user_id = u.id
                    INNER JOIN (
                        SELECT DISTINCT o.user_id
                        FROM orders o
                        WHERE o.status IN ('pending_ship','pending_recv','completed')
                          AND o.created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01')
                          AND o.created_at < DATE_ADD(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 1 MONTH)
                    ) AS active_users ON uu.user_id = active_users.user_id
                    WHERE uu.level IN (1, 2, 3)
                """)
                unilevel_users = cur.fetchall()

        if not unilevel_users:
            return {
                "pool_balance": float(pool_balance),
                "total_weight": 0,
                "amount_per_weight_auto": 0.0,
                "user_count": 0,
                "adjustment_configured": False,
                "adjusted_amount": None,
                "will_use_adjusted": False,
                "estimated_balance_after": float(pool_balance),
                "total_required": 0.0,
                "total_capped_users": 0,  # 新增
                "capped_users_list": [],  # 新增
                "users": []
            }

        # 3. 计算总权重
        total_weight = sum(Decimal(str(user['level'])) for user in unilevel_users)

        # 4. 自动计算每个权重金额
        amount_per_weight_auto = pool_balance / total_weight if total_weight > 0 else Decimal('0')

        # 5. 检查是否有手动调整配置
        adjusted_amount = self._get_adjusted_unilevel_amount()

        # 6. 确定使用哪个金额
        if adjusted_amount is not None:
            amount_per_weight = adjusted_amount
            will_use_adjusted = True
        else:
            amount_per_weight = amount_per_weight_auto
            will_use_adjusted = False

        # 7. 计算每个用户的金额并检查上限
        MAX_PER_USER = Decimal('10000')
        total_capped_users = 0
        capped_users_list = []
        users_data = []

        for user in unilevel_users:
            weight = Decimal(str(user['level']))
            theoretical_dividend = amount_per_weight * weight
            actual_dividend = min(theoretical_dividend, MAX_PER_USER)

            # 检查是否被限制
            is_capped = theoretical_dividend > actual_dividend
            if is_capped:
                total_capped_users += 1
                capped_users_list.append({
                    "user_id": user['user_id'],
                    "user_name": user['name'],
                    "weight": int(weight),
                    "theoretical_dividend": float(theoretical_dividend),
                    "actual_dividend": float(actual_dividend)
                })

            users_data.append({
                "user_id": user['user_id'],
                "user_name": user['name'],
                "unilevel_level": user['level'],
                "member_level": user['member_level'],
                "weight": int(weight),
                "theoretical_dividend": float(theoretical_dividend),  # 理论金额
                "actual_dividend": float(actual_dividend),  # 实际金额（受上限影响）
                "is_capped": is_capped  # 是否被限制
            })

        # 8. 预估扣除后的余额（基于理论最大值）
        total_theoretical_required = amount_per_weight * total_weight
        estimated_balance_after = pool_balance - total_theoretical_required

        return {
            "pool_balance": float(pool_balance),
            "total_weight": int(total_weight),
            "amount_per_weight_auto": float(amount_per_weight_auto),
            "user_count": len(unilevel_users),
            "adjustment_configured": adjusted_amount is not None,
            "adjusted_amount": float(adjusted_amount) if adjusted_amount else None,
            "will_use_adjusted": will_use_adjusted,
            "estimated_balance_after": float(estimated_balance_after),
            "total_theoretical_required": float(total_theoretical_required),
            "total_capped_users": total_capped_users,  # 达到上限的用户数
            "capped_users_list": capped_users_list,  # 被限制的用户详情
            "users": users_data
        }

    # ========== 完整函数 3：手动调整联创分红金额 ==========
    def adjust_unilevel_dividend_amount(self, amount_per_weight: Optional[float] = None) -> Dict[str, Any]:
        """
        手动调整联创星级分红金额（增加上限预警）

        Args:
            amount_per_weight: 每个权重的分红金额，传入None表示取消调整

        Returns:
            dict: 包含是否成功、消息和警告信息（如果存在用户超限）
        """
        try:
            result = {
                "success": True,
                "message": "",
                "warning": None  # 新增：警告信息
            }

            with get_conn() as conn:
                with conn.cursor() as cur:
                    if amount_per_weight is None:
                        # 取消调整
                        cur.execute(
                            "UPDATE finance_accounts SET config_params = NULL WHERE account_type = 'honor_director'"
                        )
                        result["message"] = "已取消联创分红手动调整，恢复自动计算"
                        logger.info("已取消联创分红手动调整，恢复自动计算")
                    else:
                        # 设置调整金额
                        amount = Decimal(str(amount_per_weight))
                        if amount < 0:
                            raise FinanceException("分红金额不能为负数")

                        # ==================== 新增：检查可能超限的用户 ====================
                        MAX_PER_USER = Decimal('10000')
                        cur.execute("""
                            SELECT uu.user_id, u.name, uu.level as weight
                            FROM user_unilevel uu
                            JOIN users u ON uu.user_id = u.id
                            INNER JOIN (
                                SELECT DISTINCT o.user_id
                                FROM orders o
                                WHERE o.status IN ('pending_ship','pending_recv','completed')
                                  AND o.created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01')
                                  AND o.created_at < DATE_ADD(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 1 MONTH)
                            ) AS active_users ON uu.user_id = active_users.user_id
                            WHERE uu.level IN (1, 2, 3)
                        """)
                        unilevel_users = cur.fetchall()

                        capped_users = []
                        for user in unilevel_users:
                            weight = int(user['weight'])
                            theoretical_amount = amount * Decimal(str(weight))

                            if theoretical_amount > MAX_PER_USER:
                                capped_users.append({
                                    "user_id": user['user_id'],
                                    "user_name": user['name'],
                                    "weight": weight,
                                    "theoretical_amount": float(theoretical_amount),
                                    "actual_amount": float(MAX_PER_USER)
                                })

                        # 如果有用户超限，生成警告信息
                        if capped_users:
                            max_theoretical = max(user['theoretical_amount'] for user in capped_users)
                            result["warning"] = {
                                "type": "user_dividend_cap_reached",
                                "message": f"当前设置会导致 {len(capped_users)} 个用户达到上限10,000元",
                                "capped_user_count": len(capped_users),
                                "max_theoretical_amount": float(max_theoretical),
                                "capped_users": capped_users[:10]  # 只返回前10个，避免数据过大
                            }
                            logger.warning(
                                f"联创分红手动调整设定 ¥{amount:.4f}/权重 "
                                f"将导致 {len(capped_users)} 个用户达到上限10,000元"
                            )
                        # ===================================================================

                        import json
                        config = json.dumps({"fixed_amount_per_weight": str(amount)})
                        cur.execute(
                            "UPDATE finance_accounts SET config_params = %s WHERE account_type = 'honor_director'",
                            (config,)
                        )
                        result["message"] = f"联创分红金额已调整为: ¥{amount:.4f}/权重"
                        logger.info(f"已设置联创分红手动调整: ¥{amount:.4f}/权重")

                    conn.commit()

            return result

        except Exception as e:
            logger.error(f"调整分红金额失败: {e}")
            raise

    def distribute_unilevel_dividend(self) -> bool:
        """
        发放联创星级分红（支持手动调整，新增余额保护 + 单个用户上限1万）

        关键修改：
        1. 新增：每个用户发放金额上限10,000元
        2. 保留：余额检查、资金池扣减等保护逻辑
        3. 记录：超限情况日志，便于审计
        """
        logger.info("联创星级分红发放开始（检测手动调整配置 + 用户上限1万）")

        # 查询所有联创用户
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SET time_zone = '+08:00'")

                cur.execute("""
                    SELECT uu.user_id, uu.level, u.name, u.member_level
                    FROM user_unilevel uu
                    JOIN users u ON uu.user_id = u.id
                    INNER JOIN (
                        SELECT DISTINCT o.user_id
                        FROM orders o
                        WHERE o.status IN ('pending_ship','pending_recv','completed')
                          AND o.created_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01')
                          AND o.created_at < DATE_ADD(DATE_FORMAT(CURDATE(), '%Y-%m-01'), INTERVAL 1 MONTH)
                    ) AS active_users ON uu.user_id = active_users.user_id
                    WHERE uu.level IN (1, 2, 3)
                """)
                unilevel_users = cur.fetchall()

        if not unilevel_users:
            logger.warning("没有符合条件的联创用户")
            return False

        # 计算总权重
        total_weight = sum(Decimal(str(user['level'])) for user in unilevel_users)

        # 查询分红池余额
        pool_balance = self.get_account_balance('honor_director')

        if pool_balance <= 0:
            logger.warning(f"联创分红池余额不足: ¥{pool_balance}")
            return False

        # 检查手动调整配置
        adjusted_amount = self._get_adjusted_unilevel_amount()

        # 确定使用哪个金额
        if adjusted_amount is not None:
            amount_per_weight = adjusted_amount
            total_required = amount_per_weight * total_weight

            # 关键：检查余额是否足够（在事务开始前检查）
            if total_required > pool_balance:
                raise FinanceException(
                    f"资金池余额不足。手动调整需要¥{total_required:.4f}，"
                    f"当前余额¥{pool_balance:.4f}"
                )

            logger.info(f"使用手动调整金额: ¥{amount_per_weight:.4f}/权重")
        else:
            amount_per_weight = pool_balance / total_weight
            logger.info(f"使用自动计算金额: ¥{amount_per_weight:.4f}/权重")

        # 执行分红发放
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    total_distributed = Decimal('0')
                    total_limited = 0  # 记录被限制的用户数

                    for user in unilevel_users:
                        user_id = user['user_id']
                        weight = Decimal(str(user['level']))

                        # 计算理论发放金额
                        theoretical_amount = amount_per_weight * weight

                        # ==================== 新增：限制单个用户上限10,000元 ====================
                        MAX_PER_USER = Decimal('10000.0000')
                        actual_amount = min(theoretical_amount, MAX_PER_USER)

                        if actual_amount != theoretical_amount:
                            total_limited += 1
                            logger.warning(
                                f"用户{user_id}联创分红金额超限: {theoretical_amount:.4f} -> {actual_amount:.4f} "
                                f"(权重:{weight}, 上限:{MAX_PER_USER})"
                            )
                        # ===================================================================

                        points_to_add = actual_amount

                        # 给用户发放点数
                        cur.execute(
                            "UPDATE users SET points = COALESCE(points, 0) + %s WHERE id = %s",
                            (points_to_add, user_id)
                        )

                        # 同时更新真实总点数
                        cur.execute(
                            "UPDATE users SET true_total_points = true_total_points + %s WHERE id = %s",
                            (points_to_add, user_id)
                        )

                        # 记录流水
                        cur.execute("""
                            INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                            flow_type, remark, created_at)
                            VALUES (%s, %s, %s, %s, %s, %s, NOW())
                        """, ('honor_director', user_id, points_to_add, 0, 'income',
                              f"联创{weight}星级分红（权重{weight}/{total_weight}）"))

                        # 【关键修复】从 honor_director 池扣除发放的 points_to_add
                        # 使用 _add_pool_balance（带余额保护）
                        try:
                            self._add_pool_balance(
                                cur, 'honor_director', -points_to_add,
                                f"联创星级分红发放 - 用户{user_id}获得{points_to_add:.4f}点数",
                                related_user=None
                            )
                        except InsufficientBalanceException:
                            logger.error(f"联创分红池余额不足，无法发放用户{user_id}的分红")
                            raise FinanceException("联创分红池余额不足，发放失败")

                        total_distributed += points_to_add
                        logger.debug(f"用户{user_id}获得联创星级分红: {points_to_add:.4f}点数")

                    conn.commit()

            # 分红成功后，清除手动调整配置（避免下次误用）
            if adjusted_amount is not None:
                logger.info("分红完成，清除手动调整配置")
                self.adjust_unilevel_dividend_amount(None)

            # ==================== 新增：记录被限制的用户数 ====================
            if total_limited > 0:
                logger.info(f"联创星级分红完成: 共{len(unilevel_users)}人，发放点数{total_distributed:.4f}，"
                            f"其中{total_limited}人达到上限10,000元")
            else:
                logger.info(f"联创星级分红完成: 共{len(unilevel_users)}人，发放点数{total_distributed:.4f}")
            # ===================================================================

            return True

        except InsufficientBalanceException:
            logger.error(f"❌ 联创星级分红失败: 分红池余额不足")
            raise FinanceException("联创分红池余额不足，无法完成发放")
        except Exception as e:
            logger.error(f"联创星级分红失败: {e}", exc_info=True)
            return False

    # ==================== 关键修改8：积分流水报告使用member_points ====================
    def get_points_flow_report(self, user_id: Optional[int] = None, limit: int = 50) -> List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                params = [limit]
                sql = """SELECT id, user_id, change_amount, balance_after, type, reason, related_order, created_at
                         FROM points_log WHERE type = 'member'"""
                # 修改：只查询member类型的积分流水
                if user_id:
                    sql += " AND user_id = %s"
                    params.insert(0, user_id)
                sql += " ORDER BY created_at DESC LIMIT %s"

                cur.execute(sql, tuple(params))
                flows = cur.fetchall()
                return [{
                    "id": f['id'],
                    "user_id": f['user_id'],
                    "change_amount": float(f['change_amount']),
                    "balance_after": float(f['balance_after']),
                    "type": f['type'],
                    "reason": f['reason'],
                    "related_order": f['related_order'],
                    "created_at": f['created_at'].strftime("%Y-%m-%d %H:%M:%S")
                } for f in flows]

    def get_weekly_subsidy_records(self, user_id: Optional[int] = None, limit: int = 50) -> List[Dict[str, Any]]:
        """查询周补贴记录，动态构造 SELECT 语句，对资产字段做降级默认值处理"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 先获取表结构
                cur.execute("SHOW COLUMNS FROM weekly_subsidy_records")
                columns = cur.fetchall()
                column_names = [col['Field'] for col in columns]

                # 识别资产字段关键词（数值类型字段）
                asset_keywords = ['amount', 'points', 'balance', 'total', 'frozen', 'available']
                from core.table_access import _quote_identifier

                select_fields = []
                asset_fields = []
                for col in columns:
                    field_name = col['Field']
                    field_type = col['Type'].upper()
                    # 如果是资产相关字段（字段名包含资产关键词）且为数值类型，添加降级默认值
                    is_asset_field = any(keyword in field_name.lower() for keyword in asset_keywords)
                    is_numeric_type = 'DECIMAL' in field_type or 'INT' in field_type or 'FLOAT' in field_type or 'DOUBLE' in field_type

                    if is_asset_field and is_numeric_type:
                        select_fields.append(f"COALESCE({_quote_identifier('wsr.' + field_name)}, 0) AS {_quote_identifier(field_name)}")
                        asset_fields.append(field_name)
                    else:
                        select_fields.append(_quote_identifier('wsr.' + field_name))

                # 添加用户名称字段
                select_fields.append(f"{_quote_identifier('u.name')} AS {_quote_identifier('user_name')}")

                # 构造完整的 SELECT 语句
                params = [limit]
                sql = f"""SELECT {build_select_list(select_fields)}
                         FROM weekly_subsidy_records wsr 
                         LEFT JOIN users u ON wsr.user_id = u.id"""
                if user_id:
                    sql += " WHERE wsr.user_id = %s"
                    params.insert(0, user_id)
                sql += " ORDER BY wsr.week_start DESC, wsr.id DESC LIMIT %s"

                cur.execute(sql, tuple(params))
                records = cur.fetchall()

                # 动态构造返回结果
                result = []
                for r in records:
                    record_dict = {}
                    for col_name in column_names:
                        value = r.get(col_name)
                        # 对资产字段转换为 float，其他字段保持原样
                        if col_name in asset_fields:
                            record_dict[col_name] = float(value) if value is not None else 0.0
                        elif col_name == 'week_start' and value:
                            record_dict[col_name] = value.strftime("%Y-%m-%d") if hasattr(value, 'strftime') else str(
                                value)
                        else:
                            record_dict[col_name] = value
                    # 添加用户名称
                    record_dict['user_name'] = r.get('user_name')
                    result.append(record_dict)

                return result

    # ==================== 关键修改9：积分抵扣报表使用member_points ====================
    def get_points_deduction_report(self, start_date: str, end_date: str, page: int = 1, page_size: int = 20) -> Dict[
        str, Any]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                offset = (page - 1) * page_size

                # 总数查询
                cur.execute(
                    """SELECT COUNT(*) as total
                       FROM orders o JOIN points_log pl ON o.id = pl.related_order
                       WHERE o.points_discount > 0 AND pl.type = 'member' AND pl.reason = '积分抵扣支付'
                       AND DATE(o.created_at) BETWEEN %s AND %s""",
                    (start_date, end_date)
                )
                total_count = cur.fetchone()['total']

                # 明细查询
                cur.execute(
                    """SELECT o.id as order_id, o.order_number, o.user_id, u.name as user_name, u.member_level,
                              o.original_amount, o.points_discount, o.total_amount, ABS(pl.change_amount) as points_used, o.created_at
                       FROM orders o JOIN points_log pl ON o.id = pl.related_order JOIN users u ON o.user_id = u.id
                       WHERE o.points_discount > 0 AND pl.type = 'member' AND pl.reason = '积分抵扣支付'
                       AND DATE(o.created_at) BETWEEN %s AND %s
                       ORDER BY o.created_at DESC LIMIT %s OFFSET %s""",
                    (start_date, end_date, page_size, offset)
                )
                records = cur.fetchall()

                # 汇总查询
                cur.execute(
                    """SELECT COUNT(*) as total_orders, SUM(ABS(pl.change_amount)) as total_points,
                              SUM(o.points_discount) as total_discount_amount
                       FROM orders o JOIN points_log pl ON o.id = pl.related_order
                       WHERE o.points_discount > 0 AND pl.type = 'member' AND pl.reason = '积分抵扣支付'
                       AND DATE(o.created_at) BETWEEN %s AND %s""",
                    (start_date, end_date)
                )
                summary = cur.fetchone()

                return {
                    "summary": {
                        "total_orders": summary['total_orders'] or 0,
                        # 关键修改：返回float类型的积分总量
                        "total_points_used": float(summary['total_points'] or 0),
                        "total_discount_amount": float(summary['total_discount_amount'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size
                    },
                    # 关键修改：将 order_no 改为 order_number
                    "records": [{
                        "order_id": r['order_id'],
                        "order_no": r['order_number'],  # 修复字段名
                        "user_id": r['user_id'],
                        "user_name": r['user_name'],
                        "member_level": r['member_level'],
                        "original_amount": float(r['original_amount']),
                        "points_discount": float(r['points_discount']),
                        "total_amount": float(r['total_amount']),
                        "points_used": float(r['points_used'] or 0),
                        "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S")
                    } for r in records]
                }

    # ==================== 关键修改10：交易链报表 ====================
    def get_transaction_chain_report(self, user_id: int, order_no: Optional[str] = None) -> Dict[str, Any]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 订单查询
                if order_no:
                    cur.execute(
                        """SELECT id, order_number, total_amount, original_amount, is_member_order
                           FROM orders WHERE order_number = %s AND user_id = %s""",
                        (order_no, user_id)
                    )
                else:
                    cur.execute(
                        """SELECT id, order_number, total_amount, original_amount, is_member_order
                           FROM orders WHERE user_id = %s
                           ORDER BY created_at DESC LIMIT 1""",
                        (user_id,)
                    )
                order = cur.fetchone()
                if not order:
                    logger.info(f"用户 {user_id} 无订单记录，返回空交易链")
                    return {
                        "order_id": None,
                        "order_no": None,
                        "is_member_order": False,
                        "total_amount": 0.0,
                        "original_amount": 0.0,
                        "reward_summary": {
                            "total_referral_reward": 0.0,
                            "total_team_reward": 0.0,
                            "grand_total": 0.0
                        },
                        "chain": []  # 空链
                    }
                # 构建推荐链
                chain = []
                current_id = user_id
                level = 0

                while current_id and level < MAX_TEAM_LAYER:
                    cur.execute(
                        """SELECT u.id, u.name, u.member_level, ur.referrer_id
                           FROM users u LEFT JOIN user_referrals ur ON u.id = ur.user_id
                           WHERE u.id = %s""",
                        (current_id,)
                    )
                    user_info = cur.fetchone()
                    if not user_info:
                        break

                    level += 1

                    # 动态构造 SELECT 语句
                    select_fields, existing_columns = _build_team_rewards_select(cur, ['reward_amount'])
                    # 确保包含 created_at 字段（如果不存在则使用 NULL）
                    if 'created_at' not in existing_columns:
                        select_fields = select_fields + ", NULL AS created_at"

                    cur.execute(
                        f"SELECT {select_fields} FROM team_rewards WHERE order_id = %s AND layer = %s",
                        (order['id'], level)
                    )
                    team_reward = cur.fetchone()

                    referral_reward = None
                    if level == 1:
                        cur.execute(
                            """SELECT amount FROM pending_rewards
                               WHERE order_id = %s AND reward_type = 'referral' AND status = 'approved'""",
                            (order['id'],)
                        )
                        ref_reward = cur.fetchone()
                        if ref_reward:
                            referral_reward = float(ref_reward['amount'])

                    chain.append({
                        "layer": level,
                        "user_id": user_info['id'],
                        "name": user_info['name'],
                        "member_level": user_info['member_level'],
                        "is_referrer": (level == 1),
                        "referral_reward": referral_reward,
                        "team_reward": {
                            "amount": float(team_reward['reward_amount']) if team_reward else 0.00,
                            "has_reward": team_reward is not None
                        },
                        "referrer_id": user_info['referrer_id']
                    })

                    if not user_info['referrer_id']:
                        break
                    current_id = user_info['referrer_id']

                total_referral = chain[0]['referral_reward'] if chain and chain[0]['referral_reward'] else 0.00
                total_team = sum(item['team_reward']['amount'] for item in chain)

                # 关键修改：将 order_no 改为 order_number
                return {
                    "order_id": order['id'],
                    "order_no": order['order_number'],  # 修复字段名
                    "is_member_order": bool(order['is_member_order']),
                    "total_amount": float(order['total_amount']),
                    "original_amount": float(order['original_amount']),
                    "reward_summary": {
                        "total_referral_reward": total_referral,
                        "total_team_reward": total_team,
                        "grand_total": total_referral + total_team
                    },
                    "chain": chain
                }

    # ==================== 1. 优惠券直接发放 ====================
    # 在 services/finance_service.py 中

    def distribute_coupon_directly(self, user_id: int, amount: float,
                                   coupon_type: str = 'user',
                                   applicable_product_type: str = 'all',  # 新增参数
                                   valid_days: int = COUPON_VALID_DAYS) -> int:
        """直接发放优惠券给用户（需扣除等额的 true_total_points）"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # ========== 检查 true_total_points 余额 ==========
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="id=%s",
                        select_fields=["true_total_points"]
                    )
                    cur.execute(select_sql, (user_id,))
                    user_row = cur.fetchone()

                    if not user_row:
                        raise FinanceException(f"用户不存在: {user_id}")

                    current_balance = Decimal(str(user_row.get('true_total_points', 0) or 0))
                    coupon_amount = Decimal(str(amount))

                    if current_balance < coupon_amount:
                        raise FinanceException(
                            f"用户 true_total_points 余额不足，当前余额: {current_balance:.4f}，"
                            f"需要 {coupon_amount:.4f}（发放优惠券 ¥{amount:.2f}）"
                        )

                    # ========== 发放优惠券 ==========
                    today = datetime.now().date()
                    valid_to = today + timedelta(days=valid_days)

                    cur.execute(
                        """INSERT INTO coupons (user_id, coupon_type, amount, applicable_product_type, valid_from, valid_to, status)
                           VALUES (%s, %s, %s, %s, %s, %s, 'unused')""",
                        (user_id, coupon_type, coupon_amount, applicable_product_type, today, valid_to)
                    )
                    coupon_id = cur.lastrowid

                    # ========== 扣除 true_total_points ==========
                    new_balance = current_balance - coupon_amount
                    cur.execute(
                        "UPDATE users SET true_total_points = %s WHERE id = %s",
                        (new_balance, user_id)
                    )

                    # ========== 记录扣除流水 ==========
                    cur.execute(
                        """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                           flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                        ('true_total_points', user_id, -coupon_amount, new_balance, 'expense',
                         f"发放优惠券扣除 - 优惠券#{coupon_id}，金额¥{coupon_amount:.2f}，类型:{applicable_product_type}")
                    )

                    conn.commit()

                    logger.debug(f"发放优惠券给用户{user_id}: ID={coupon_id}, 金额¥{coupon_amount:.2f}, "
                                 f"类型:{applicable_product_type}, 扣除 true_total_points {coupon_amount:.4f}")
                    return coupon_id

        except FinanceException:
            raise
        except Exception as e:
            logger.error(f"❌ 直接发放优惠券失败: {e}")
            raise FinanceException(f"发放失败: {e}")

    # ==================== 2. 查询推荐奖励列表 ====================
    def get_referral_rewards(self, user_id: Optional[int] = None,
                             status: str = 'approved',  # 现在只支持 'approved' 或 'all'
                             page: int = 1,
                             page_size: int = 20) -> Dict[str, Any]:
        """查询推荐奖励自动发放记录"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建查询条件
                where_conditions = ["af.account_type = 'referral_points' AND af.flow_type = 'income'"]
                params = []

                if user_id:
                    where_conditions.append("af.related_user = %s")
                    params.append(user_id)

                where_sql = " AND ".join(where_conditions)

                # 查询总数
                cur.execute(f"SELECT COUNT(*) as total FROM account_flow af WHERE {where_sql}", tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 查询明细
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT af.id, af.related_user as user_id, u.name as user_name,
                           af.change_amount as points_issued, af.remark,
                           af.created_at, u.referral_points as current_points
                    FROM account_flow af
                    JOIN users u ON af.related_user = u.id
                    WHERE {where_sql}
                    ORDER BY af.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                return {
                    "total_count": total_count,
                    "page": page,
                    "page_size": page_size,
                    "records": [
                        {
                            "reward_id": r['id'],
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "points_issued": str(r['points_issued']),
                            "current_points_balance": str(r['current_points'] or 0),
                            "status": "已自动发放",
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "points_field": "referral_points",
                            "remark": r['remark']
                        } for r in records
                    ]
                }
    # ==================== 3. 推荐和团队奖励流水合并查询 ====================
    def get_reward_flow_report(self, user_id: Optional[int] = None,
                               reward_type: Optional[str] = None,
                               start_date: Optional[str] = None,
                               end_date: Optional[str] = None,
                               page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """查询奖励自动发放流水明细（从 account_flow 查询）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建查询条件
                where_conditions = [
                    "af.flow_type = 'income' AND af.account_type IN ('referral_points', 'team_reward_points')"]
                params = []

                if user_id:
                    where_conditions.append("af.related_user = %s")
                    params.append(user_id)

                if reward_type:
                    where_conditions.append("af.account_type = %s")
                    params.append(f"{reward_type}_points")

                if start_date:
                    where_conditions.append("DATE(af.created_at) >= %s")
                    params.append(start_date)

                if end_date:
                    where_conditions.append("DATE(af.created_at) <= %s")
                    params.append(end_date)

                where_sql = " AND ".join(where_conditions)

                # 查询总数
                cur.execute(f"SELECT COUNT(*) as total FROM account_flow af WHERE {where_sql}", tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 查询明细
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT af.id, af.related_user as user_id, u.name as user_name,
                           af.account_type, af.change_amount as points_issued,
                           af.remark, af.created_at,
                           CASE af.account_type 
                             WHEN 'referral_points' THEN u.referral_points 
                             WHEN 'team_reward_points' THEN u.team_reward_points 
                             ELSE 0 
                           END as current_points
                    FROM account_flow af
                    JOIN users u ON af.related_user = u.id
                    WHERE {where_sql}
                    ORDER BY af.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                # 汇总统计
                summary_sql = f"""
                    SELECT 
                        COUNT(*) as total_records,
                        SUM(CASE WHEN account_type = 'referral_points' THEN change_amount ELSE 0 END) as total_referral_points,
                        SUM(CASE WHEN account_type = 'team_reward_points' THEN change_amount ELSE 0 END) as total_team_points
                    FROM account_flow af
                    WHERE {where_sql}
                """
                cur.execute(summary_sql, tuple(params[:-2]))
                summary = cur.fetchone()

                return {
                    "summary": {
                        "total_records": summary['total_records'] or 0,
                        "total_referral_points": str(summary.get('total_referral_points', 0) or 0),
                        "total_team_points": str(summary.get('total_team_points', 0) or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "flow_id": r['id'],
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "reward_type": '推荐' if 'referral' in r['account_type'] else '团队',
                            "points_issued": str(r['points_issued']),
                            "current_points_balance": str(r['current_points'] or 0),
                            "remark": r['remark'],
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "points_field": r['account_type'],
                            "status": "已自动发放"
                        } for r in records
                    ]
                }

    # ==================== 4. 优惠券使用（消失）- 增强流水记录 ====================
    def use_coupon(self, coupon_id: int, user_id: int, order_type: str = None) -> bool:
        """使用优惠券，验证商品类型匹配性"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 1. 查询优惠券详情
                    cur.execute(
                        """SELECT c.*, u.name as user_name
                           FROM coupons c JOIN users u ON c.user_id = u.id
                           WHERE c.id = %s AND c.user_id = %s AND c.status = 'unused'""",
                        (coupon_id, user_id)
                    )
                    coupon = cur.fetchone()

                    if not coupon:
                        raise FinanceException("优惠券不存在或已使用")

                    # 2. 验证有效期
                    today = datetime.now().date()
                    if not (coupon['valid_from'] <= today <= coupon['valid_to']):
                        raise FinanceException("优惠券不在有效期内")

                    # 3. 验证商品类型匹配（如果提供了订单类型）
                    if order_type:
                        applicable_type = coupon['applicable_product_type']
                        if applicable_type == 'normal_only' and order_type == 'member':
                            raise FinanceException("该优惠券仅限普通商品使用")
                        if applicable_type == 'member_only' and order_type == 'normal':
                            raise FinanceException("该优惠券仅限会员商品使用")

                    # 4. 标记为已使用
                    cur.execute(
                        "UPDATE coupons SET status = 'used', used_at = NOW() WHERE id = %s",
                        (coupon_id,)
                    )

                    # 5. 记录使用流水
                    cur.execute(
                        """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                           flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                        ('coupon', user_id, Decimal('0'), Decimal('0'), 'expense',
                         f"用户使用优惠券 - 优惠券#{coupon_id}，金额¥{float(coupon['amount'])}, 类型:{coupon['applicable_product_type']}")
                    )

                    conn.commit()
                    logger.debug(f"用户{user_id}使用优惠券{coupon_id}:¥{coupon['amount']:.2f}成功")
                    return True

        except FinanceException as e:
            raise
        except Exception as e:
            logger.error(f"❌ 使用优惠券失败: {e}")
            raise

    # ==================== 提现申请处理报表（高优先级） ====================
    def get_withdrawal_report(self, start_date: str, end_date: str,
                              user_id: Optional[int] = None,
                              status: Optional[str] = None,
                              page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """
        提现申请处理报表

        统计提现申请的数量、金额、税费、实际到账金额及各状态分布
        """
        logger.info(f"生成提现申请报表: 日期范围={start_date}至{end_date}, 用户={user_id}, 状态={status}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建WHERE条件 - ✅ 使用表别名w.避免歧义
                where_conditions = ["DATE(w.created_at) BETWEEN %s AND %s"]  # ✅ w.created_at
                params = [start_date, end_date]

                if user_id:
                    where_conditions.append("w.user_id = %s")  # ✅ w.user_id
                    params.append(user_id)

                if status:
                    where_conditions.append("w.status = %s")  # ✅ w.status
                    params.append(status)

                where_sql = " AND ".join(where_conditions)

                # 汇总统计 - ✅ 所有表名都使用别名w.
                summary_sql = f"""
                    SELECT 
                        COUNT(*) as total_applications,
                        SUM(w.amount) as total_amount,
                        SUM(w.tax_amount) as total_tax,
                        SUM(w.actual_amount) as total_actual_amount,
                        SUM(CASE WHEN w.status = 'approved' THEN 1 ELSE 0 END) as approved_count,
                        SUM(CASE WHEN w.status = 'rejected' THEN 1 ELSE 0 END) as rejected_count,
                        SUM(CASE WHEN w.status = 'pending_auto' THEN 1 ELSE 0 END) as pending_auto_count,
                        SUM(CASE WHEN w.status = 'pending_manual' THEN 1 ELSE 0 END) as pending_manual_count
                    FROM withdrawals w
                    WHERE {where_sql}
                """
                cur.execute(summary_sql, tuple(params))
                summary = cur.fetchone()

                # 总记录数 - ✅ 使用别名w.
                count_sql = f"SELECT COUNT(*) as total FROM withdrawals w WHERE {where_sql}"
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 明细查询 - ✅ 使用别名w.和u.
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT 
                        w.id, w.user_id, u.name as user_name,
                        w.amount, w.tax_amount, w.actual_amount, w.status,
                        w.created_at, w.processed_at, w.audit_remark
                    FROM withdrawals w
                    JOIN users u ON w.user_id = u.id
                    WHERE {where_sql}
                    ORDER BY w.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                # 返回数据
                return {
                    "summary": {
                        "report_type": "withdrawal_processing",
                        "total_applications": summary['total_applications'] or 0,
                        "total_amount": float(summary['total_amount'] or 0),
                        "total_tax": float(summary['total_tax'] or 0),
                        "total_actual_amount": float(summary['total_actual_amount'] or 0),
                        "approved_count": summary['approved_count'] or 0,
                        "rejected_count": summary['rejected_count'] or 0,
                        "pending_auto_count": summary['pending_auto_count'] or 0,
                        "pending_manual_count": summary['pending_manual_count'] or 0,
                        "pending_total_count": (summary['pending_auto_count'] or 0) + (
                                    summary['pending_manual_count'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "withdrawal_id": r['id'],
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "amount": float(r['amount']),
                            "tax_amount": float(r['tax_amount']),
                            "actual_amount": float(r['actual_amount']),
                            "status": r['status'],
                            "status_text": {
                                "pending_auto": "自动审核中",
                                "pending_manual": "人工审核中",
                                "approved": "已批准",
                                "rejected": "已拒绝"
                            }.get(r['status'], "未知"),
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "processed_at": r['processed_at'].strftime("%Y-%m-%d %H:%M:%S") if r[
                                'processed_at'] else None,
                            "audit_remark": r['audit_remark']
                        } for r in records
                    ]
                }
    # ==================== 总会员积分明细报表（新增） ====================
    def get_member_points_detail_report(self, user_id: Optional[int] = None,
                                        start_date: Optional[str] = None,
                                        end_date: Optional[str] = None,
                                        page: int = 1,
                                        page_size: int = 20) -> Dict[str, Any]:
        """
        总会员积分明细报表

        关键修复：
        1. 修复汇总查询的参数传递逻辑
        2. 确保 WHERE 条件与参数数量匹配
        3. 不影响原有功能和逻辑
        """
        logger.info(f"生成总会员积分明细报表: 用户={user_id or '所有用户'}, 日期范围={start_date}至{end_date}")

        from datetime import datetime, date

        # 构建WHERE条件
        where_conditions = ["pl.type = 'member'"]
        params = []

        if user_id:
            where_conditions.append("pl.user_id = %s")
            params.append(user_id)

        if start_date:
            where_conditions.append("DATE(pl.created_at) >= %s")
            params.append(start_date)

        if end_date:
            where_conditions.append("DATE(pl.created_at) <= %s")
            params.append(end_date)

        where_sql = " AND ".join(where_conditions)

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 查询总记录数
                count_sql = f"""
                    SELECT COUNT(*) as total 
                    FROM points_log pl
                    WHERE {where_sql}
                """
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 2. 查询期初余额
                opening_balance = Decimal('0')
                if start_date and user_id:
                    cur.execute("""
                        SELECT balance_after 
                        FROM points_log 
                        WHERE user_id = %s AND type = 'member' AND DATE(created_at) < %s
                        ORDER BY created_at DESC 
                        LIMIT 1
                    """, (user_id, start_date))
                    opening_row = cur.fetchone()
                    if opening_row:
                        opening_balance = Decimal(str(opening_row['balance_after'] or 0))

                # 3. 查询明细（分页）
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT 
                        pl.id as log_id,
                        pl.user_id,
                        u.name as user_name,
                        pl.change_amount,
                        pl.balance_after,
                        pl.reason,
                        pl.related_order,
                        pl.created_at
                    FROM points_log pl
                    JOIN users u ON pl.user_id = u.id
                    LEFT JOIN orders o ON pl.related_order = o.id
                    WHERE {where_sql}
                    ORDER BY pl.created_at DESC, pl.id DESC
                    LIMIT %s OFFSET %s
                """
                # 注意：参数是 params + [page_size, offset]
                query_params = params + [page_size, offset]
                cur.execute(detail_sql, tuple(query_params))
                records = cur.fetchall()

                # 4. 汇总统计（关键修复：正确处理参数）
                # 汇总查询应该使用同样的 where_conditions，但移除分页参数
                summary_sql = f"""
                    SELECT 
                        COUNT(*) as total_records,
                        SUM(CASE WHEN pl.change_amount > 0 THEN pl.change_amount ELSE 0 END) as total_income,
                        SUM(CASE WHEN pl.change_amount < 0 THEN ABS(pl.change_amount) ELSE 0 END) as total_expense,
                        SUM(pl.change_amount) as net_change
                    FROM points_log pl
                    WHERE {where_sql}
                """
                # 关键修复：使用与 count_sql 相同的参数
                cur.execute(summary_sql, tuple(params))
                summary = cur.fetchone()

                # 5. 计算期末余额
                closing_balance = Decimal('0')
                if user_id:
                    # 【查询单个用户】从明细记录或用户表获取期末余额
                    if records:
                        closing_balance = Decimal(str(records[0]['balance_after'] or 0))
                    else:
                        cur.execute("""
                            SELECT COALESCE(member_points, 0) as current_balance
                            FROM users 
                            WHERE id = %s
                        """, (user_id,))
                        balance_row = cur.fetchone()
                        closing_balance = Decimal(str(balance_row['current_balance'] if balance_row else 0))
                else:
                    # 【查询所有用户】计算总积分作为期末余额
                    cur.execute("""
                        SELECT COALESCE(SUM(member_points), 0) as total_balance
                        FROM users
                    """)
                    total_row = cur.fetchone()
                    closing_balance = Decimal(str(total_row['total_balance'] if total_row else 0))

                # 6. 获取用户信息
                user_info = None
                if user_id and records:
                    user_info = {
                        "user_id": records[0]['user_id'],
                        "user_name": records[0]['user_name']
                    }

                return {
                    "summary": {
                        "report_type": "member_points_detail",
                        "query_date_range": f"{start_date or '开始'} 至 {end_date or '结束'}",
                        "user_filter": user_id or "所有用户",
                        "opening_balance": float(opening_balance),
                        "closing_balance": float(closing_balance),
                        "total_records": summary['total_records'] or 0,
                        "total_income": float(summary['total_income'] or 0),
                        "total_expense": float(summary['total_expense'] or 0),
                        "net_change": float(summary['net_change'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "user_info": user_info,
                    "records": [
                        {
                            "log_id": r['log_id'],
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "change_amount": float(r['change_amount'] or 0),
                            "balance_after": float(r['balance_after'] or 0),
                            "flow_type": "收入" if r['change_amount'] > 0 else "支出",
                            "reason": r['reason'],
                            "related_order_id": r['related_order'],
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S") if r['created_at'] else None
                        } for r in records
                    ]
                }
    # ==================== 平台资金池变动报表（中优先级） ====================
    def get_pool_flow_report(self, account_type: str,
                             start_date: str, end_date: str,
                             page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        logger.info(f"生成资金池流水报表: 账户={account_type}, 日期范围={start_date}至{end_date}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 查询平台余额
                cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", (account_type,))
                account_row = cur.fetchone()
                actual_current_balance = Decimal(str(account_row['balance'] if account_row else 0))

                # 智能过滤：只对 honor_director 强制过滤
                where_conditions = [
                    "account_type = %s",
                    "DATE(created_at) BETWEEN %s AND %s"
                ]
                params = [account_type, start_date, end_date]

                # 只有联创分红池才过滤 related_user=NULL
                if account_type == 'honor_director':
                    where_conditions.append("related_user IS NULL")

                where_sql = " AND ".join(where_conditions)

                # 汇总统计（保持Decimal类型，不转换为float）
                cur.execute(f"""
                    SELECT 
                        COUNT(*) as total_transactions,
                        SUM(CASE WHEN flow_type = 'income' THEN change_amount ELSE 0 END) as total_income,
                        SUM(CASE WHEN flow_type = 'expense' THEN change_amount ELSE 0 END) as total_expense
                    FROM account_flow
                    WHERE {where_sql}
                """, tuple(params))
                summary = cur.fetchone()

                # 总记录数
                cur.execute(f"SELECT COUNT(*) as total FROM account_flow WHERE {where_sql}", tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 明细查询
                offset = (page - 1) * page_size
                cur.execute(f"""
                    SELECT 
                        id, related_user, change_amount, balance_after, 
                        flow_type, remark, created_at
                    FROM account_flow
                    WHERE {where_sql}
                    ORDER BY created_at DESC, id DESC
                    LIMIT %s OFFSET %s
                """, tuple(params + [page_size, offset]))
                records = cur.fetchall()

                # 获取用户名称
                def get_user_name(uid):
                    if not uid:
                        return "系统"
                    if uid == 0:
                        return "平台"
                    try:
                        cur.execute("SELECT name FROM users WHERE id = %s", (uid,))
                        row = cur.fetchone()
                        return row['name'] if row else f"未知用户:{uid}"
                    except Exception:
                        return f"查询失败:{uid}"

                # 计算净变动（保持Decimal类型）
                total_income = Decimal(str(summary['total_income'] or 0))
                total_expense = Decimal(str(summary['total_expense'] or 0))
                net_change = total_income - total_expense

                # 账户类型中文名称映射
                account_name_map = {
                    "public_welfare": "公益基金",
                    "subsidy_pool": "周补贴池",
                    "honor_director": "荣誉董事分红池",
                    "company_points": "公司积分池",
                    "platform_revenue_pool": "平台收入池",
                    "maintain_pool": "平台维护池",
                    "director_pool": "荣誉董事池",
                    "shop_pool": "社区店池",
                    "city_pool": "城市运营中心池",
                    "branch_pool": "大区分公司池",
                    "fund_pool": "事业发展基金池",
                    "merchant_balance": "商户余额池"
                }

                # 返回数据（关键修改：不再转换为float）
                return {
                    "summary": {
                        "report_type": "pool_flow",
                        "account_type": account_type,
                        "account_name": account_name_map.get(account_type, account_type),
                        "total_transactions": summary['total_transactions'] or 0,
                        "total_income": total_income,  # 保持Decimal类型
                        "total_expense": total_expense,  # 保持Decimal类型
                        "net_change": net_change,  # 保持Decimal类型
                        "ending_balance": actual_current_balance,  # 保持Decimal类型
                        "query_date_range": f"{start_date} 至 {end_date}"
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "flow_id": r['id'],
                            "related_user": r['related_user'],
                            "user_name": get_user_name(r['related_user']),
                            "change_amount": r['change_amount'],  # 保持原始Decimal类型
                            "balance_after": r['balance_after'],  # 保持原始Decimal类型
                            "flow_type": r['flow_type'],
                            "remark": r['remark'],
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S")
                        } for r in records
                    ],
                    "data_source": "finance_accounts + account_flow",
                    "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
    # ==================== 联创星级点数流水报表 ====================
    def get_unilevel_points_flow_report(self, user_id: Optional[int] = None,
                                        level: Optional[int] = None,
                                        start_date: Optional[str] = None,
                                        end_date: Optional[str] = None,
                                        page: int = 1,
                                        page_size: int = 20) -> Dict[str, Any]:
        """
        联创星级点数流水报表（修正版：从account_flow表查询）

        查询联创会员的星级分红发放记录，支持按用户、星级、日期筛选
        """
        logger.info(f"生成联创星级点数流水报表: 用户={user_id}, 星级={level}, 日期范围={start_date}至{end_date}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建WHERE条件（用于明细和汇总查询）
                where_conditions = ["af.account_type = 'honor_director'", "af.flow_type = 'income'"]
                query_params = []

                if user_id:
                    where_conditions.append("af.related_user = %s")
                    query_params.append(user_id)

                if level:
                    where_conditions.append("uu.level = %s")
                    query_params.append(level)

                if start_date:
                    where_conditions.append("DATE(af.created_at) >= %s")
                    query_params.append(start_date)

                if end_date:
                    where_conditions.append("DATE(af.created_at) <= %s")
                    query_params.append(end_date)

                where_sql = " AND ".join(where_conditions)

                # 1. 总记录数查询
                count_sql = f"""
                    SELECT COUNT(*) as total
                    FROM account_flow af
                    JOIN user_unilevel uu ON af.related_user = uu.user_id
                    WHERE {where_sql}
                """
                cur.execute(count_sql, tuple(query_params))
                total_count = cur.fetchone()['total'] or 0

                # 2. 明细查询（带分页）
                offset = (page - 1) * page_size
                detail_params = query_params + [page_size, offset]
                detail_sql = f"""
                    SELECT af.id as flow_id, af.related_user as user_id, u.name as user_name,
                           uu.level as unilevel_level, af.change_amount as points,
                           af.created_at, af.remark
                    FROM account_flow af
                    JOIN users u ON af.related_user = u.id
                    JOIN user_unilevel uu ON af.related_user = uu.user_id
                    WHERE {where_sql}
                    ORDER BY af.created_at DESC, af.id DESC
                    LIMIT %s OFFSET %s
                """
                cur.execute(detail_sql, tuple(detail_params))
                records = cur.fetchall()

                # 3. 汇总统计（不包含user_id过滤条件）
                summary_where = where_conditions.copy()
                summary_params = query_params.copy()

                # 移除user_id相关的条件（如果存在）
                if user_id:
                    user_idx = -1
                    for idx, condition in enumerate(summary_where):
                        if "af.related_user" in condition:
                            user_idx = idx
                            break
                    if user_idx >= 0:
                        summary_where.pop(user_idx)
                        summary_params.pop(user_idx)

                summary_sql = f"""
                    SELECT COUNT(DISTINCT af.related_user) as total_users,
                           SUM(af.change_amount) as total_dividend_amount
                    FROM account_flow af
                    JOIN user_unilevel uu ON af.related_user = uu.user_id
                    WHERE {" AND ".join(summary_where)}
                """
                cur.execute(summary_sql, tuple(summary_params))
                summary = cur.fetchone()

                return {
                    "summary": {
                        "report_type": "unilevel_points_flow",
                        "total_users": summary['total_users'] or 0,
                        "total_dividend_amount": float(summary['total_dividend_amount'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "flow_id": r['flow_id'],
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "unilevel_level": r['unilevel_level'],
                            "level_name": f"{r['unilevel_level']}星级联创",
                            "points": float(r['points'] or 0),
                            "period_date": r['created_at'].strftime("%Y-%m-%d"),
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "remark": r['remark']
                        } for r in records
                    ]
                }

    def clear_fund_pools(self, pool_types: List[str]) -> Dict[str, Any]:
        """清空指定的资金池（增加余额保护）"""
        logger.info(f"开始清空资金池: {pool_types}")

        if not pool_types:
            raise FinanceException("必须指定要清空的资金池类型")

        # 验证所有池子类型是否有效
        valid_pools = [key.value for key in AllocationKey]
        for pool_type in pool_types:
            if pool_type not in valid_pools:
                raise FinanceException(f"无效的资金池类型: {pool_type}")

        # 事务外查询余额
        pools_to_clear = []
        for pool_type in pool_types:
            current_balance = self.get_account_balance(pool_type)
            if current_balance <= 0:
                logger.debug(f"资金池 {pool_type} 余额为0，跳过")
                continue

            # 获取账户名称
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT account_name FROM finance_accounts WHERE account_type = %s",
                        (pool_type,)
                    )
                    account = cur.fetchone()
                    account_name = account['account_name'] if account else pool_type

            pools_to_clear.append({
                "account_type": pool_type,
                "account_name": account_name,
                "balance": current_balance
            })

        if not pools_to_clear:
            logger.info("所有指定资金池余额为0，无需清空")
            return {
                "cleared_pools": [],
                "total_cleared": 0.0
            }

        cleared_pools = []
        total_cleared = Decimal('0')

        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    for pool_info in pools_to_clear:
                        pool_type = pool_info["account_type"]
                        account_name = pool_info["account_name"]
                        current_balance = pool_info["balance"]

                        # 执行清空操作（使用 _add_pool_balance 带余额保护）
                        try:
                            self._add_pool_balance(
                                cur, pool_type, -current_balance,
                                f"手动清空资金池 - 清空金额¥{current_balance:.2f}",
                                related_user=None
                            )

                            cleared_pools.append({
                                "account_type": pool_type,
                                "account_name": account_name,
                                "amount_cleared": float(current_balance),
                                "previous_balance": float(current_balance)
                            })
                            total_cleared += current_balance

                            logger.info(f"已清空资金池 {pool_type}: ¥{current_balance:.2f}")
                        except InsufficientBalanceException:
                            logger.error(f"资金池 {pool_type} 余额不足，无法清空")
                            raise FinanceException(f"资金池 {pool_type} 余额不足，清空失败")

                    conn.commit()

            logger.info(f"资金池清空完成: 共清空 {len(cleared_pools)} 个，总计 ¥{total_cleared:.2f}")

            return {
                "cleared_pools": cleared_pools,
                "total_cleared": float(total_cleared)
            }

        except Exception as e:
            logger.error(f"清空资金池失败: {e}", exc_info=True)
            raise

    def get_weekly_subsidy_report(self, year: int, week: int, user_id: Optional[int] = None,
                                  page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """周补贴明细报表（显示发放点数和余额变化）"""
        logger.info(f"生成周补贴报表: {year}年第{week}周")

        from datetime import date, timedelta

        # 计算周的开始和结束日期
        first_day = date(year, 1, 1)
        if first_day.weekday() > 0:
            first_day += timedelta(days=7 - first_day.weekday())
        elif first_day.weekday() == 6:
            first_day += timedelta(days=1)

        week_start = first_day + timedelta(weeks=week - 1)
        week_end = week_start + timedelta(days=6)

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建WHERE条件
                where_conditions = ["wsr.week_start BETWEEN %s AND %s"]
                params = [week_start, week_end]

                if user_id:
                    where_conditions.append("wsr.user_id = %s")
                    params.append(user_id)

                where_sql = " AND ".join(where_conditions)

                # 总记录数查询
                count_sql = f"""
                    SELECT COUNT(*) as total 
                    FROM weekly_subsidy_records wsr 
                    WHERE {where_sql}
                """
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 明细查询（增加发放前后余额）
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT wsr.user_id, u.name as user_name, wsr.week_start,
                           wsr.subsidy_amount, wsr.points_before, wsr.points_deducted,
                           u.subsidy_points as current_subsidy_points,
                           (u.subsidy_points - wsr.points_deducted) as subsidy_points_before
                    FROM weekly_subsidy_records wsr
                    JOIN users u ON wsr.user_id = u.id
                    WHERE {where_sql}
                    ORDER BY wsr.user_id, wsr.week_start DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                # 汇总统计
                summary_sql = f"""
                    SELECT COUNT(DISTINCT wsr.user_id) as total_users,
                           SUM(wsr.subsidy_amount) as total_subsidy_amount,
                           SUM(wsr.points_deducted) as total_points_issued
                    FROM weekly_subsidy_records wsr
                    WHERE {where_sql.replace(' AND wsr.user_id = %s', '') if user_id else where_sql}
                """
                if user_id:
                    cur.execute(summary_sql, (week_start, week_end))
                else:
                    cur.execute(summary_sql, tuple(params[:-2]))
                summary = cur.fetchone()

                return {
                    "summary": {
                        "query_week": f"{year}-W{week:02d}",
                        "week_start": week_start.strftime("%Y-%m-%d"),
                        "week_end": week_end.strftime("%Y-%m-%d"),
                        "total_users": summary['total_users'] or 0,
                        "total_subsidy_amount": float(summary['total_subsidy_amount'] or 0),
                        "total_points_issued": float(summary['total_points_issued'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "week_start": r['week_start'].strftime("%Y-%m-%d"),
                            "subsidy_amount": float(r['subsidy_amount'] or 0),
                            "points_issued": float(r['points_deducted'] or 0),  # 实际发放点数
                            "member_points_before": float(r['points_before'] or 0),  # 参与计算的积分
                            "subsidy_points_before": float(r['subsidy_points_before'] or 0),  # 发放前余额
                            "subsidy_points_after": float(r['current_subsidy_points'] or 0),  # 发放后余额
                            "remark": f"发放补贴点数{float(r['points_deducted'] or 0):.4f}，扣减积分{float(r['points_before'] or 0):.4f}"
                        } for r in records
                    ],
                    "points_flow": {
                        "source_field": "member_points",
                        "target_field": "subsidy_points",
                        "action": "积分兑换补贴点数"
                    }
                }

    def get_monthly_subsidy_report(self, year: int, month: int, user_id: Optional[int] = None,
                                   page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """月补贴明细报表

        查询指定年月的补贴发放明细（按周汇总）

        Args:
            year: 年份，如2025
            month: 月份，1-12
            user_id: 用户ID（可选）
            page: 页码
            page_size: 每页条数

        Returns:
            包含汇总、分页和明细的字典
        """
        logger.info(f"生成月补贴报表: {year}年{month}月")

        from datetime import date
        import calendar

        # 计算月的开始和结束日期
        _, last_day = calendar.monthrange(year, month)
        month_start = date(year, month, 1)
        month_end = date(year, month, last_day)

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建WHERE条件
                where_conditions = ["wsr.week_start BETWEEN %s AND %s"]
                params = [month_start, month_end]

                if user_id:
                    where_conditions.append("wsr.user_id = %s")
                    params.append(user_id)

                where_sql = " AND ".join(where_conditions)

                # 总记录数查询
                count_sql = f"""
                    SELECT COUNT(*) as total 
                    FROM weekly_subsidy_records wsr 
                    WHERE {where_sql}
                """
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 明细查询
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT wsr.user_id, u.name as user_name, wsr.week_start,
                           wsr.subsidy_amount, wsr.points_before, wsr.points_deducted,
                           wsr.coupon_id
                    FROM weekly_subsidy_records wsr
                    JOIN users u ON wsr.user_id = u.id
                    WHERE {where_sql}
                    ORDER BY wsr.user_id, wsr.week_start DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                # 汇总统计
                summary_sql = f"""
                    SELECT COUNT(DISTINCT wsr.user_id) as total_users,
                           SUM(wsr.subsidy_amount) as total_subsidy_amount,
                           SUM(wsr.points_deducted) as total_points_deducted
                    FROM weekly_subsidy_records wsr
                    WHERE {where_sql.replace(' AND wsr.user_id = %s', '') if user_id else where_sql}
                """
                if user_id:
                    cur.execute(summary_sql, (month_start, month_end))
                else:
                    cur.execute(summary_sql, tuple(params[:-2]))
                summary = cur.fetchone()

                return {
                    "summary": {
                        "query_month": f"{year}-{month:02d}",
                        "month_start": month_start.strftime("%Y-%m-%d"),
                        "month_end": month_end.strftime("%Y-%m-%d"),
                        "total_users": summary['total_users'] or 0,
                        "total_subsidy_amount": float(summary['total_subsidy_amount'] or 0),
                        "total_points_deducted": float(summary['total_points_deducted'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "week_start": r['week_start'].strftime("%Y-%m-%d"),
                            "subsidy_amount": float(r['subsidy_amount'] or 0),
                            "points_before": float(r['points_before'] or 0),
                            "points_deducted": float(r['points_deducted'] or 0),
                            "points_after": float((r['points_before'] or 0) - (r['points_deducted'] or 0)),
                            "coupon_id": r['coupon_id'],
                            "remark": f"发放补贴¥{float(r['subsidy_amount'] or 0):.2f}，扣减积分{float(r['points_deducted'] or 0):.4f}"
                        } for r in records
                    ]
                }

    # services/finance_service.py

    # ... 在 get_monthly_subsidy_report 方法之后添加 ...

    def get_weekly_member_points_report(self, year: int, week: int, user_id: Optional[int] = None,
                                        page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """用户积分周报表

        查询指定周次内用户member_points的变动明细

        Args:
            year: 年份，如2025
            week: 周数，1-53
            user_id: 用户ID（可选）
            page: 页码
            page_size: 每页条数

        Returns:
            包含汇总、分页和明细的字典
        """
        logger.info(f"生成用户积分周报表: {year}年第{week}周")

        from datetime import date, timedelta

        # 计算周的开始和结束日期
        first_day = date(year, 1, 1)
        if first_day.weekday() > 0:
            first_day += timedelta(days=7 - first_day.weekday())
        elif first_day.weekday() == 6:
            first_day += timedelta(days=1)

        week_start = first_day + timedelta(weeks=week - 1)
        week_end = week_start + timedelta(days=6)

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建WHERE条件
                where_conditions = ["DATE(pl.created_at) BETWEEN %s AND %s", "pl.type = 'member'"]
                params = [week_start, week_end]

                if user_id:
                    where_conditions.append("pl.user_id = %s")
                    params.append(user_id)

                where_sql = " AND ".join(where_conditions)

                # 总记录数查询
                count_sql = f"""
                    SELECT COUNT(*) as total 
                    FROM points_log pl
                    WHERE {where_sql}
                """
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 明细查询
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT pl.id, pl.user_id, u.name as user_name,
                           pl.change_amount, pl.balance_after, pl.reason,
                           pl.related_order, pl.created_at
                    FROM points_log pl
                    JOIN users u ON pl.user_id = u.id
                    WHERE {where_sql}
                    ORDER BY pl.user_id, pl.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                # 汇总统计
                summary_sql = f"""
                    SELECT COUNT(DISTINCT pl.user_id) as total_users,
                           SUM(CASE WHEN pl.change_amount > 0 THEN pl.change_amount ELSE 0 END) as total_income,
                           SUM(CASE WHEN pl.change_amount < 0 THEN ABS(pl.change_amount) ELSE 0 END) as total_expense,
                           SUM(pl.change_amount) as net_change
                    FROM points_log pl
                    WHERE {where_sql.replace(' AND pl.user_id = %s', '') if user_id else where_sql}
                """
                if user_id:
                    cur.execute(summary_sql, (week_start, week_end))
                else:
                    cur.execute(summary_sql, tuple(params[:-2]))
                summary = cur.fetchone()

                return {
                    "summary": {
                        "report_type": "member_points_weekly",
                        "query_week": f"{year}-W{week:02d}",
                        "week_start": week_start.strftime("%Y-%m-%d"),
                        "week_end": week_end.strftime("%Y-%m-%d"),
                        "total_users": summary['total_users'] or 0,
                        "total_income": float(summary['total_income'] or 0),
                        "total_expense": float(summary['total_expense'] or 0),
                        "net_change": float(summary['net_change'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "log_id": r['id'],
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "change_amount": float(r['change_amount'] or 0),
                            "balance_after": float(r['balance_after'] or 0),
                            "reason": r['reason'],
                            "related_order": r['related_order'],
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "flow_type": "收入" if r['change_amount'] > 0 else "支出"
                        } for r in records
                    ]
                }

    def get_monthly_member_points_report(self, year: int, month: int, user_id: Optional[int] = None,
                                         page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """用户积分月报表

        查询指定年月内用户member_points的变动明细

        Args:
            year: 年份，如2025
            month: 月份，1-12
            user_id: 用户ID（可选）
            page: 页码
            page_size: 每页条数

        Returns:
            包含汇总、分页和明细的字典
        """
        logger.info(f"生成用户积分月报表: {year}年{month}月")

        from datetime import date
        import calendar

        # 计算月的开始和结束日期
        _, last_day = calendar.monthrange(year, month)
        month_start = date(year, month, 1)
        month_end = date(year, month, last_day)

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建WHERE条件
                where_conditions = ["DATE(pl.created_at) BETWEEN %s AND %s", "pl.type = 'member'"]
                params = [month_start, month_end]

                if user_id:
                    where_conditions.append("pl.user_id = %s")
                    params.append(user_id)

                where_sql = " AND ".join(where_conditions)

                # 总记录数查询
                count_sql = f"""
                    SELECT COUNT(*) as total 
                    FROM points_log pl
                    WHERE {where_sql}
                """
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 明细查询
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT pl.id, pl.user_id, u.name as user_name,
                           pl.change_amount, pl.balance_after, pl.reason,
                           pl.related_order, pl.created_at
                    FROM points_log pl
                    JOIN users u ON pl.user_id = u.id
                    WHERE {where_sql}
                    ORDER BY pl.user_id, pl.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                # 汇总统计
                summary_sql = f"""
                    SELECT COUNT(DISTINCT pl.user_id) as total_users,
                           SUM(CASE WHEN pl.change_amount > 0 THEN pl.change_amount ELSE 0 END) as total_income,
                           SUM(CASE WHEN pl.change_amount < 0 THEN ABS(pl.change_amount) ELSE 0 END) as total_expense,
                           SUM(pl.change_amount) as net_change
                    FROM points_log pl
                    WHERE {where_sql.replace(' AND pl.user_id = %s', '') if user_id else where_sql}
                """
                if user_id:
                    cur.execute(summary_sql, (month_start, month_end))
                else:
                    cur.execute(summary_sql, tuple(params[:-2]))
                summary = cur.fetchone()

                return {
                    "summary": {
                        "report_type": "member_points_monthly",
                        "query_month": f"{year}-{month:02d}",
                        "month_start": month_start.strftime("%Y-%m-%d"),
                        "month_end": month_end.strftime("%Y-%m-%d"),
                        "total_users": summary['total_users'] or 0,
                        "total_income": float(summary['total_income'] or 0),
                        "total_expense": float(summary['total_expense'] or 0),
                        "net_change": float(summary['net_change'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "log_id": r['id'],
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "change_amount": float(r['change_amount'] or 0),
                            "balance_after": float(r['balance_after'] or 0),
                            "reason": r['reason'],
                            "related_order": r['related_order'],
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "flow_type": "收入" if r['change_amount'] > 0 else "支出"
                        } for r in records
                    ]
                }

    def get_weekly_merchant_points_report(self, year: int, week: int, user_id: Optional[int] = None,
                                          page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """商家积分周报表

        查询指定周次内商家merchant_points的变动明细
        """
        logger.info(f"生成商家积分周报表: {year}年第{week}周")

        from datetime import date, timedelta

        first_day = date(year, 1, 1)
        if first_day.weekday() > 0:
            first_day += timedelta(days=7 - first_day.weekday())
        elif first_day.weekday() == 6:
            first_day += timedelta(days=1)

        week_start = first_day + timedelta(weeks=week - 1)
        week_end = week_start + timedelta(days=6)

        with get_conn() as conn:
            with conn.cursor() as cur:
                where_conditions = ["DATE(pl.created_at) BETWEEN %s AND %s", "pl.type = 'merchant'"]
                params = [week_start, week_end]

                if user_id:
                    where_conditions.append("pl.user_id = %s")
                    params.append(user_id)

                where_sql = " AND ".join(where_conditions)

                # 总记录数
                count_sql = f"SELECT COUNT(*) as total FROM points_log pl WHERE {where_sql}"
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 明细
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT pl.id, pl.user_id, u.name as user_name,
                           pl.change_amount, pl.balance_after, pl.reason,
                           pl.related_order, pl.created_at
                    FROM points_log pl
                    JOIN users u ON pl.user_id = u.id
                    WHERE {where_sql}
                    ORDER BY pl.user_id, pl.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                # 汇总
                summary_sql = f"""
                    SELECT COUNT(DISTINCT pl.user_id) as total_users,
                           SUM(CASE WHEN pl.change_amount > 0 THEN pl.change_amount ELSE 0 END) as total_income,
                           SUM(CASE WHEN pl.change_amount < 0 THEN ABS(pl.change_amount) ELSE 0 END) as total_expense,
                           SUM(pl.change_amount) as net_change
                    FROM points_log pl
                    WHERE {where_sql.replace(' AND pl.user_id = %s', '') if user_id else where_sql}
                """
                if user_id:
                    cur.execute(summary_sql, (week_start, week_end))
                else:
                    cur.execute(summary_sql, tuple(params[:-2]))
                summary = cur.fetchone()

                return {
                    "summary": {
                        "report_type": "merchant_points_weekly",
                        "query_week": f"{year}-W{week:02d}",
                        "week_start": week_start.strftime("%Y-%m-%d"),
                        "week_end": week_end.strftime("%Y-%m-%d"),
                        "total_users": summary['total_users'] or 0,
                        "total_income": float(summary['total_income'] or 0),
                        "total_expense": float(summary['total_expense'] or 0),
                        "net_change": float(summary['net_change'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "log_id": r['id'],
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "change_amount": float(r['change_amount'] or 0),
                            "balance_after": float(r['balance_after'] or 0),
                            "reason": r['reason'],
                            "related_order": r['related_order'],
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "flow_type": "收入" if r['change_amount'] > 0 else "支出"
                        } for r in records
                    ]
                }

    def get_monthly_merchant_points_report(self, year: int, month: int, user_id: Optional[int] = None,
                                           page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """商家积分月报表"""
        logger.info(f"生成商家积分月报表: {year}年{month}月")

        from datetime import date
        import calendar

        _, last_day = calendar.monthrange(year, month)
        month_start = date(year, month, 1)
        month_end = date(year, month, last_day)

        with get_conn() as conn:
            with conn.cursor() as cur:
                where_conditions = ["DATE(pl.created_at) BETWEEN %s AND %s", "pl.type = 'merchant'"]
                params = [month_start, month_end]

                if user_id:
                    where_conditions.append("pl.user_id = %s")
                    params.append(user_id)

                where_sql = " AND ".join(where_conditions)

                # 总记录数
                count_sql = f"SELECT COUNT(*) as total FROM points_log pl WHERE {where_sql}"
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 明细
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT pl.id, pl.user_id, u.name as user_name,
                           pl.change_amount, pl.balance_after, pl.reason,
                           pl.related_order, pl.created_at
                    FROM points_log pl
                    JOIN users u ON pl.user_id = u.id
                    WHERE {where_sql}
                    ORDER BY pl.user_id, pl.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                # 汇总
                summary_sql = f"""
                    SELECT COUNT(DISTINCT pl.user_id) as total_users,
                           SUM(CASE WHEN pl.change_amount > 0 THEN pl.change_amount ELSE 0 END) as total_income,
                           SUM(CASE WHEN pl.change_amount < 0 THEN ABS(pl.change_amount) ELSE 0 END) as total_expense,
                           SUM(pl.change_amount) as net_change
                    FROM points_log pl
                    WHERE {where_sql.replace(' AND pl.user_id = %s', '') if user_id else where_sql}
                """
                if user_id:
                    cur.execute(summary_sql, (month_start, month_end))
                else:
                    cur.execute(summary_sql, tuple(params[:-2]))
                summary = cur.fetchone()

                return {
                    "summary": {
                        "report_type": "merchant_points_monthly",
                        "query_month": f"{year}-{month:02d}",
                        "month_start": month_start.strftime("%Y-%m-%d"),
                        "month_end": month_end.strftime("%Y-%m-%d"),
                        "total_users": summary['total_users'] or 0,
                        "total_income": float(summary['total_income'] or 0),
                        "total_expense": float(summary['total_expense'] or 0),
                        "net_change": float(summary['net_change'] or 0)
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": [
                        {
                            "log_id": r['id'],
                            "user_id": r['user_id'],
                            "user_name": r['user_name'],
                            "change_amount": float(r['change_amount'] or 0),
                            "balance_after": float(r['balance_after'] or 0),
                            "reason": r['reason'],
                            "related_order": r['related_order'],
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "flow_type": "收入" if r['change_amount'] > 0 else "支出"
                        } for r in records
                    ]
                }

    def get_weekly_subsidy_preview(self, year: int, week: int, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """周补贴预览报表（全用户）"""
        logger.info(f"生成全用户周补贴预览报表: {year}年第{week}周，页码={page}")

        from datetime import date, timedelta

        # 计算周的开始和结束日期
        first_day = date(year, 1, 1)
        if first_day.weekday() > 0:
            first_day += timedelta(days=7 - first_day.weekday())
        elif first_day.weekday() == 6:
            first_day += timedelta(days=1)

        week_start = first_day + timedelta(weeks=week - 1)
        week_end = week_start + timedelta(days=6)

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 获取补贴池余额
                pool_balance = self.get_account_balance('subsidy_pool')

                # 2. 计算系统总积分
                structure = get_table_structure(cur, "users", use_cache=False)

                # 用户积分总计
                if "member_points" in structure['fields']:
                    cur.execute(
                        "SELECT SUM(COALESCE(member_points, 0)) as total FROM users WHERE COALESCE(member_points, 0) > 0")
                    row = cur.fetchone()
                    total_user_points = Decimal(str(row.get('total', 0) or 0))
                else:
                    total_user_points = Decimal('0')

                # 商家积分总计
                if "merchant_points" in structure['fields']:
                    cur.execute(
                        "SELECT SUM(COALESCE(merchant_points, 0)) as total FROM users WHERE COALESCE(merchant_points, 0) > 0")
                    row = cur.fetchone()
                    total_merchant_points = Decimal(str(row.get('total', 0) or 0))
                else:
                    total_merchant_points = Decimal('0')

                # 公司积分池
                cur.execute("SELECT balance as total FROM finance_accounts WHERE account_type = 'company_points'")
                row = cur.fetchone()
                company_points = Decimal(str(row.get('total', 0) or 0))

                total_points = total_user_points + total_merchant_points + company_points

                # 3. 计算积分价值（先检查手动调整）
                adjusted_points_value = self._get_adjusted_points_value()

                if adjusted_points_value is not None:
                    # 使用手动调整的积分值
                    points_value = adjusted_points_value
                    is_manual_adjusted = True
                    logger.info(f"预览使用手动调整的积分值: {points_value:.4f}")
                else:
                    # 按原方案自动计算
                    points_value = pool_balance / total_points if total_points > 0 else Decimal('0')
                    if points_value > MAX_POINTS_VALUE:
                        points_value = MAX_POINTS_VALUE
                    is_manual_adjusted = False

                # 4. 查询所有有积分的用户（分页）
                offset = (page - 1) * page_size

                # 获取总用户数
                cur.execute("SELECT COUNT(*) as total FROM users WHERE COALESCE(member_points, 0) > 0")
                total_users = cur.fetchone()['total'] or 0

                # 获取分页用户数据
                cur.execute(
                    """SELECT id, name, member_points 
                       FROM users 
                       WHERE COALESCE(member_points, 0) > 0
                       ORDER BY member_points DESC, id
                       LIMIT %s OFFSET %s""",
                    (page_size, offset)
                )
                users = cur.fetchall()

                # 5. 计算每个用户的预计补贴
                user_records = []
                for user in users:
                    user_points = Decimal(str(user.get('member_points') or 0))
                    estimated_coupon = user_points * points_value

                    user_records.append({
                        "user_id": user['id'],
                        "user_name": user['name'],
                        "member_points": float(user_points),
                        "estimated_points_amount": float(estimated_coupon),
                        "points_percentage": float(user_points / total_points * 100) if total_points > 0 else 0.0
                    })

                logger.info(f"全用户周补贴预览生成完成: 共{len(user_records)}条记录")

                return {
                    "summary": {
                        "report_type": "weekly_subsidy_preview_all_users",
                        "query_week": f"{year}-W{week:02d}",
                        "week_start": week_start.strftime("%Y-%m-%d"),
                        "week_end": week_end.strftime("%Y-%m-%d"),
                        "total_users_with_points": total_users,
                        "subsidy_pool_balance": float(pool_balance),
                        "total_system_points": float(total_points),
                        "points_value_per_point": float(points_value),
                        "max_points_value_applied": points_value >= MAX_POINTS_VALUE,
                        "is_manual_adjusted": is_manual_adjusted  # 新增：是否手动调整
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_users,
                        "total_pages": (total_users + page_size - 1) // page_size if total_users > 0 else 1
                    },
                    "calculation_details": {
                        "total_user_points": float(total_user_points),
                        "total_merchant_points": float(total_merchant_points),
                        "company_points": float(company_points)
                    },
                    "user_records": user_records,
                    "remark": "按member_points降序排列，支持分页查询"
                }


    def get_order_points_flow_report(self, start_date: str, end_date: str,
                                     user_id: Optional[int] = None,
                                     order_no: Optional[str] = None,
                                     page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """
        订单积分流水报告（精简版：仅包含积分数据）

        查询订单相关的积分流动情况，包括：
        - 订单产生的用户积分
        - 订单产生的商户积分
        - 订单使用的积分抵扣
        - 退款时的积分回滚

        Args:
            start_date: 开始日期 yyyy-MM-dd
            end_date: 结束日期 yyyy-MM-dd
            user_id: 用户ID（可选）
            order_no: 订单号（可选）
            page: 页码
            page_size: 每页条数

        Returns:
            包含汇总统计、分页信息和流水明细的字典
        """
        logger.info(f"生成订单积分流水报告: 日期范围={start_date}至{end_date}, 用户={user_id}, 订单号={order_no}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 构建WHERE条件
                where_conditions = ["DATE(o.created_at) BETWEEN %s AND %s"]
                params = [start_date, end_date]

                if user_id:
                    where_conditions.append("o.user_id = %s")
                    params.append(user_id)

                if order_no:
                    where_conditions.append("o.order_number = %s")
                    params.append(order_no)

                where_sql = " AND ".join(where_conditions)

                # 2. 查询订单总数
                count_sql = f"""
                    SELECT COUNT(DISTINCT o.id) as total
                    FROM orders o
                    WHERE {where_sql}
                """
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 3. 分页查询订单明细
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT 
                        o.id as order_id,
                        o.order_number,
                        o.user_id,
                        u.name as user_name,
                        o.total_amount,
                        o.original_amount,
                        o.points_discount,
                        o.is_member_order,
                        o.created_at,
                        o.status
                    FROM orders o
                    JOIN users u ON o.user_id = u.id
                    WHERE {where_sql}
                    ORDER BY o.created_at DESC
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                orders = cur.fetchall()

                # 4. 查询每个订单的积分数据
                order_ids = [order['order_id'] for order in orders]
                order_addons_map = {}

                if order_ids:
                    placeholders, params_dict = build_in_placeholders(order_ids)
                    params_tuple = tuple(params_dict[f"id{i}"] for i in range(len(order_ids)))

                    # 仅查询积分流水
                    cur.execute(f"""
                        SELECT 
                            pl.related_order,
                            SUM(CASE WHEN pl.type = 'member' AND pl.change_amount > 0 THEN pl.change_amount ELSE 0 END) as user_earned,
                            SUM(CASE WHEN pl.type = 'member' AND pl.change_amount < 0 THEN ABS(pl.change_amount) ELSE 0 END) as points_deducted,
                            SUM(CASE WHEN pl.type = 'merchant' THEN pl.change_amount ELSE 0 END) as merchant_earned
                        FROM points_log pl
                        WHERE pl.related_order IN ({placeholders})
                        GROUP BY pl.related_order
                    """, params_tuple)

                    for row in cur.fetchall():
                        order_addons_map[row['related_order']] = {
                            'user_earned': float(row['user_earned'] or 0),
                            'points_deducted': float(row['points_deducted'] or 0),
                            'merchant_earned': float(row['merchant_earned'] or 0)
                        }

                # 5. 汇总统计
                # 汇总订单数据
                if user_id:
                    summary_params = params[:-2]
                else:
                    summary_params = params[:-2]

                summary_sql = f"""
                    SELECT 
                        COUNT(o.id) as total_orders,
                        SUM(CASE WHEN o.status='completed' THEN 1 ELSE 0 END) as completed_orders,
                        SUM(o.original_amount) as total_original_amount,
                        SUM(o.points_discount) as total_points_deduction,
                        SUM(o.total_amount) as total_net_sales
                    FROM orders o
                    WHERE {where_sql} AND o.status != 'refunded'
                """
                cur.execute(summary_sql, tuple(summary_params))
                summary = cur.fetchone()

                # 汇总积分数据
                total_user_points = total_deducted_points = total_merchant_points = 0
                if order_ids:
                    # 总用户积分
                    cur.execute(f"""
                        SELECT SUM(change_amount) as total_user_points
                        FROM points_log
                        WHERE type = 'member' AND change_amount > 0
                          AND related_order IN ({placeholders})
                    """, params_tuple)
                    total_user_points = cur.fetchone()['total_user_points'] or 0

                    # 总抵扣积分
                    cur.execute(f"""
                            SELECT SUM(ABS(change_amount)) as total_deducted_points
                            FROM points_log
                            WHERE type = 'member' AND change_amount < 0
                                AND related_order IN ({placeholders})
                    """, params_tuple)
                    total_deducted_points = cur.fetchone()['total_deducted_points'] or 0

                    # 总商户积分
                    cur.execute(f"""
                            SELECT SUM(change_amount) as total_merchant_points
                            FROM points_log
                            WHERE type = 'merchant'
                                AND related_order IN ({placeholders})
                    """, params_tuple)
                    total_merchant_points = cur.fetchone()['total_merchant_points'] or 0

                # 6. 构建返回数据
                records = []
                for order in orders:
                    order_id = order['order_id']
                    addons = order_addons_map.get(order_id, {
                        'user_earned': 0,
                        'points_deducted': 0,
                        'merchant_earned': 0
                    })

                    # 计算积分抵扣率
                    deduction_rate = (order['points_discount'] / order['original_amount'] * 100) if order[
                                                                                                        'original_amount'] > 0 else 0

                    records.append({
                        "order_id": order_id,
                        "order_no": order['order_number'],
                        "user_id": order['user_id'],
                        "user_name": order['user_name'],
                        "order_type": "会员订单" if order['is_member_order'] else "普通订单",
                        "status": order['status'],
                        "status_text": {
                            "pending_pay": "待支付",
                            "pending_ship": "待发货",
                            "pending_recv": "待收货",
                            "completed": "已完成",
                            "refund": "退款中",
                            "refunded": "已退款"
                        }.get(order['status'], "未知"),
                        "original_amount": float(order['original_amount']),
                        "points_deduction": float(order['points_discount']),
                        "net_sales": float(order['total_amount']),
                        "user_points_earned": addons['user_earned'],
                        "merchant_points_earned": addons['merchant_earned'],
                        "created_at": order['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                        "deduction_rate": f"{deduction_rate:.1f}%"
                    })

                return {
                    "summary": {
                        "report_type": "order_points_flow",
                        "date_range": f"{start_date} 至 {end_date}",
                        "total_orders": summary['total_orders'] or 0,
                        "completed_orders": summary['completed_orders'] or 0,
                        "total_original_amount": float(summary['total_original_amount'] or 0),
                        "total_points_deduction": float(summary['total_points_deduction'] or 0),
                        "total_net_sales": float(summary['total_net_sales'] or 0),
                        "total_user_points_issued": float(total_user_points),
                        "total_points_deducted": float(total_deducted_points),
                        "total_merchant_points_issued": float(total_merchant_points),
                        "average_deduction_rate": f"{(summary['total_points_deduction'] or 0) / (summary['total_original_amount'] or 1) * 100:.2f}%"
                    },
                    "pagination": {
                        "page": page,
                        "page_size": page_size,
                        "total": total_count,
                        "total_pages": (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    "records": records,
                    "remark": "数据包含所有订单的积分流动及商户积分发放情况"
                }

    def get_all_points_flow_report(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        查询所有点数类型的流水报表（仅包含点数，不包含积分）

        数据来源：
        1. account_flow: 推荐、团队、联创、true_total_points 流水（收入和支出）
        2. weekly_subsidy_records: 周补贴点数发放记录（补贴点数收入）
        3. 不包含 points_log（这是积分流水，不是点数流水）

        Args:
            user_id: 用户ID（可选，不传则查询所有用户）

        Returns:
            包含各点数类型统计和明细的字典
        """
        logger.info(f"生成纯点数流水报表: 用户={user_id or '所有用户'}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建用户查询条件
                user_where = "WHERE u.id = %s" if user_id else ""
                user_params = [user_id] if user_id else []

                # 查询所有用户（包括没有点数的，显示为0）
                sql = f"""
                    SELECT u.id, u.name,
                        COALESCE(u.subsidy_points, 0) as subsidy_balance,
                        COALESCE(u.referral_points, 0) as referral_balance,
                        COALESCE(u.team_reward_points, 0) as team_balance,
                        COALESCE(u.points, 0) as unilevel_balance,
                        COALESCE(u.true_total_points, 0) as true_total_balance
                    FROM users u
                    {user_where}
                    ORDER BY u.id
                """
                cur.execute(sql, tuple(user_params))
                users = cur.fetchall()

                if not users:
                    return {
                        "summary": {
                            "total_users": 0,
                            "report_type": "all_points_flow",
                            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        },
                        "users": []
                    }

                # 批量查询各类点数收入
                user_ids = [u['id'] for u in users]
                income_map = {uid: {
                    'subsidy_points': Decimal('0'),
                    'referral_points': Decimal('0'),
                    'team_reward_points': Decimal('0'),
                    'honor_director': Decimal('0'),
                    'true_total_points': Decimal('0')  # 支出用负数表示
                } for uid in [u['id'] for u in users]}

                if user_ids:
                    placeholders, params_dict = build_in_placeholders(user_ids)
                    params_tuple = tuple(params_dict[f"id{i}"] for i in range(len(user_ids)))

                    # 从 account_flow 查询点数收入（flow_type='income'）
                    # account_type: referral_points, team_reward_points, honor_director, true_total_points
                    cur.execute(f"""
                        SELECT 
                            related_user,
                            account_type,
                            SUM(CASE WHEN flow_type = 'income' THEN change_amount ELSE 0 END) as total_income,
                            SUM(CASE WHEN flow_type = 'expense' THEN change_amount ELSE 0 END) as total_expense
                        FROM account_flow
                        WHERE related_user IN ({placeholders})
                            AND account_type IN ('referral_points', 'team_reward_points', 'honor_director', 'true_total_points')
                        GROUP BY related_user, account_type
                    """, params_tuple)

                    for row in cur.fetchall():
                        uid = row['related_user']
                        account_type = row['account_type']
                        net_change = Decimal(str(row['total_income'] or 0)) - Decimal(
                            str(abs(row['total_expense'] or 0)))

                        if uid in income_map:
                            # true_total_points 的支出是负数
                            if account_type == 'true_total_points':
                                income_map[uid][account_type] = -Decimal(str(abs(row['total_expense'] or 0)))
                            else:
                                income_map[uid][account_type] = Decimal(str(row['total_income'] or 0))

                    # 从 weekly_subsidy_records 查询周补贴点数收入
                    cur.execute(f"""
                        SELECT 
                            user_id,
                            SUM(subsidy_amount) as total_subsidy_income
                        FROM weekly_subsidy_records
                        WHERE user_id IN ({placeholders})
                        GROUP BY user_id
                    """, params_tuple)

                    for row in cur.fetchall():
                        uid = row['user_id']
                        if uid in income_map:
                            income_map[uid]['subsidy_points'] = Decimal(str(row['total_subsidy_income'] or 0))

                # 组装结果（不包含积分流水）
                result = []
                for user in users:
                    uid = user['id']
                    user_income = income_map.get(uid, {
                        'subsidy_points': Decimal('0'),
                        'referral_points': Decimal('0'),
                        'team_reward_points': Decimal('0'),
                        'honor_director': Decimal('0'),
                        'true_total_points': Decimal('0')
                    })

                    # 当前余额
                    subsidy_balance = Decimal(str(user['subsidy_balance']))
                    referral_balance = Decimal(str(user['referral_balance']))
                    team_balance = Decimal(str(user['team_balance']))
                    unilevel_balance = Decimal(str(user['unilevel_balance']))
                    true_total_balance = Decimal(str(user['true_total_balance']))

                    # 各项点数累计收入
                    subsidy_income = user_income['subsidy_points']
                    referral_income = user_income['referral_points']
                    team_income = user_income['team_reward_points']
                    unilevel_income = user_income['honor_director']
                    # true_total_points 的变动来自优惠券发放（扣减）
                    true_total_deduction = abs(user_income['true_total_points'])  # 转换为正数显示

                    # 计算消耗（点数一般没有消耗逻辑，主要计算净收入）
                    # 如果当前余额 < 总收入，说明有部分已使用
                    subsidy_expense = max(Decimal('0'), subsidy_income - subsidy_balance)
                    referral_expense = max(Decimal('0'), referral_income - referral_balance)
                    team_expense = max(Decimal('0'), team_income - team_balance)
                    unilevel_expense = max(Decimal('0'), unilevel_income - unilevel_balance)

                    result.append({
                        "user_id": uid,
                        "user_name": user['name'],
                        "points_summary": {
                            "subsidy_points": {
                                "current_balance": str(subsidy_balance),
                                "total_earned": str(subsidy_income),
                                "total_used": str(subsidy_expense),
                                "remark": "周补贴专用点数（从 member_points 转换而来）"
                            },
                            "referral_points": {
                                "current_balance": str(referral_balance),
                                "total_earned": str(referral_income),
                                "total_used": str(referral_expense),
                                "remark": "推荐奖励专用点数"
                            },
                            "team_reward_points": {
                                "current_balance": str(team_balance),
                                "total_earned": str(team_income),
                                "total_used": str(team_expense),
                                "remark": "团队奖励专用点数"
                            },
                            "unilevel_points": {
                                "current_balance": str(unilevel_balance),
                                "total_earned": str(unilevel_income),
                                "total_used": str(unilevel_expense),
                                "remark": "联创星级分红专用点数"
                            },
                            "true_total_points": {
                                "current_balance": str(true_total_balance),
                                "total_deducted": str(true_total_deduction),  # 优惠券发放导致的扣减
                                "remark": "真实总点数（用于优惠券兑换）"
                            }
                        },
                        "grand_total": {
                            "total_balance": str(
                                true_total_balance
                            ),
                            "total_earned": str(
                                subsidy_income + referral_income + team_income + unilevel_income
                            ),
                            "total_deducted": str(true_total_deduction)  # 优惠券扣减
                        }
                    })

                return {
                    "summary": {
                        "total_users": len(result),
                        "report_type": "all_points_flow",
                        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "remark": "仅包含点数流水，不包含积分流水（如周补贴扣减积分）"
                    },
                    "users": result
                }

    # ==================== 周补贴点数报表 ====================
    def get_subsidy_points_report(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """查询周补贴点数明细报表"""
        logger.info(f"生成周补贴点数报表: 用户={user_id or '所有用户'}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                user_where = "WHERE u.id = %s" if user_id else ""
                user_params = [user_id] if user_id else []

                sql = f"""
                    SELECT u.id, u.name, COALESCE(u.subsidy_points, 0) as current_balance
                    FROM users u
                    {user_where}
                    ORDER BY u.id
                """
                cur.execute(sql, tuple(user_params))
                users = cur.fetchall()

                if not users:
                    return {"summary": {"total_users": 0, "report_type": "subsidy_points"}, "users": []}

                # 查询累计收入
                user_ids = [u['id'] for u in users]
                income_map = {}
                if user_ids:
                    placeholders, params_dict = build_in_placeholders(user_ids)
                    params_tuple = tuple(params_dict[f"id{i}"] for i in range(len(user_ids)))
                    cur.execute(f"""
                        SELECT related_user, COALESCE(SUM(change_amount), 0) as total_income
                        FROM account_flow
                        WHERE related_user IN ({placeholders})
                            AND account_type = 'subsidy_points' AND flow_type = 'income'
                        GROUP BY related_user
                    """, params_tuple)

                    for row in cur.fetchall():
                        income_map[row['related_user']] = Decimal(str(row['total_income']))

                result = []
                for user in users:
                    uid = user['id']
                    current_balance = Decimal(str(user['current_balance']))
                    total_earned = income_map.get(uid, Decimal('0'))
                    total_used = max(Decimal('0'), total_earned - current_balance)

                    result.append({
                        "user_id": uid,
                        "user_name": user['name'],
                        "current_balance": float(current_balance),
                        "total_earned": float(total_earned),
                        "total_used": float(total_used),
                        "remark": "周补贴专用点数"
                    })

                return {
                    "summary": {
                        "total_users": len(result),
                        "report_type": "subsidy_points",
                        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    },
                    "users": result
                }
    # ==================== 联创星级点数报表 ====================
    def get_unilevel_points_report(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """查询联创星级点数明细报表"""
        logger.info(f"生成联创星级点数报表: 用户={user_id or '所有用户'}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                user_where = "WHERE u.id = %s" if user_id else ""
                user_params = [user_id] if user_id else []

                sql = f"""
                    SELECT u.id, u.name, COALESCE(u.points, 0) as current_balance
                    FROM users u
                    {user_where}
                    ORDER BY u.id
                """
                cur.execute(sql, tuple(user_params))
                users = cur.fetchall()

                if not users:
                    return {"summary": {"total_users": 0, "report_type": "unilevel_points"}, "users": []}

                # 查询累计收入
                user_ids = [u['id'] for u in users]
                income_map = {}
                if user_ids:
                    placeholders, params_dict = build_in_placeholders(user_ids)
                    params_tuple = tuple(params_dict[f"id{i}"] for i in range(len(user_ids)))
                    cur.execute(f"""
                        SELECT related_user, COALESCE(SUM(change_amount), 0) as total_income
                        FROM account_flow
                        WHERE related_user IN ({placeholders})
                            AND account_type = 'honor_director' AND flow_type = 'income'
                        GROUP BY related_user
                    """, params_tuple)

                    for row in cur.fetchall():
                        income_map[row['related_user']] = Decimal(str(row['total_income']))

                result = []
                for user in users:
                    uid = user['id']
                    current_balance = Decimal(str(user['current_balance']))
                    total_earned = income_map.get(uid, Decimal('0'))
                    total_used = max(Decimal('0'), total_earned - current_balance)

                    result.append({
                        "user_id": uid,
                        "user_name": user['name'],
                        "current_balance": float(current_balance),
                        "total_earned": float(total_earned),
                        "total_used": float(total_used),
                        "remark": "联创星级分红专用点数"
                    })

                return {
                    "summary": {
                        "total_users": len(result),
                        "report_type": "unilevel_points",
                        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    },
                    "users": result
                }

    # ==================== 推荐+团队合并点数报表 ====================
    def get_referral_and_team_points_report(self, user_id: Optional[int] = None) -> Dict[str, Any]:
        """
        推荐奖励和团队奖励合并点数报表

        输出三项数据：
        1. referral_points - 推荐奖励点数
        2. team_reward_points - 团队奖励点数
        3. combined_total - 推荐和团队点数合计
        """
        logger.info(f"生成推荐+团队合并点数报表: 用户={user_id or '所有用户'}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                user_where = "WHERE u.id = %s" if user_id else ""
                user_params = [user_id] if user_id else []

                sql = f"""
                    SELECT u.id, u.name,
                        COALESCE(u.referral_points, 0) as referral_balance,
                        COALESCE(u.team_reward_points, 0) as team_balance
                    FROM users u
                    {user_where}
                    ORDER BY u.id
                """
                cur.execute(sql, tuple(user_params))
                users = cur.fetchall()

                if not users:
                    return {"summary": {"total_users": 0, "report_type": "referral_and_team_points"}, "users": []}

                # 批量查询累计收入
                user_ids = [u['id'] for u in users]
                income_map = {}

                if user_ids:
                    placeholders, params_dict = build_in_placeholders(user_ids)
                    params_tuple = tuple(params_dict[f"id{i}"] for i in range(len(user_ids)))
                    cur.execute(f"""
                        SELECT 
                            related_user,
                            account_type,
                            COALESCE(SUM(change_amount), 0) as total_income
                        FROM account_flow
                        WHERE related_user IN ({placeholders})
                            AND account_type IN ('referral_points', 'team_reward_points')
                            AND flow_type = 'income'
                        GROUP BY related_user, account_type
                    """, params_tuple)

                    for row in cur.fetchall():
                        uid = row['related_user']
                        if uid not in income_map:
                            income_map[uid] = {}
                        income_map[uid][row['account_type']] = Decimal(str(row['total_income']))

                result = []
                for user in users:
                    uid = user['id']
                    user_income = income_map.get(uid, {})

                    # 推荐奖励
                    referral_balance = Decimal(str(user['referral_balance']))
                    referral_earned = user_income.get('referral_points', Decimal('0'))
                    referral_used = max(Decimal('0'), referral_earned - referral_balance)

                    # 团队奖励
                    team_balance = Decimal(str(user['team_balance']))
                    team_earned = user_income.get('team_reward_points', Decimal('0'))
                    team_used = max(Decimal('0'), team_earned - team_balance)

                    # 合并总计
                    combined_balance = referral_balance + team_balance
                    combined_earned = referral_earned + team_earned
                    combined_used = referral_used + team_used

                    result.append({
                        "user_id": uid,
                        "user_name": user['name'],
                        "referral_points": {
                            "current_balance": float(referral_balance),
                            "total_earned": float(referral_earned),
                            "total_used": float(referral_used),
                            "remark": "推荐奖励专用点数"
                        },
                        "team_points": {
                            "current_balance": float(team_balance),
                            "total_earned": float(team_earned),
                            "total_used": float(team_used),
                            "remark": "团队奖励专用点数"
                        },
                        "combined_total": {
                            "total_balance": float(combined_balance),
                            "total_earned": float(combined_earned),
                            "total_used": float(combined_used),
                            "remark": "推荐+团队点数合计"
                        }
                    })

                return {
                    "summary": {
                        "total_users": len(result),
                        "report_type": "referral_and_team_points",
                        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    },
                    "users": result
                }

    def get_all_points_flow_report_v2(self, user_id: Optional[int] = None,
                                      start_date: Optional[str] = None,
                                      end_date: Optional[str] = None,
                                      page: int = 1,
                                      page_size: int = 20) -> Dict[str, Any]:
        """
        综合点数流水报表（整合四种点数收入和优惠券扣减）

        重要字段映射：
        - honor_director     → users.points              （联创星级）
        - subsidy_points     → users.subsidy_points      （周补贴）
        - referral_points    → users.referral_points     （推荐奖励）
        - team_reward_points → users.team_reward_points  （团队奖励）
        - true_total_points  → users.true_total_points   （真实总点数）
        """
        logger.info(f"生成综合点数流水报表: 用户={user_id or '所有用户'}, 日期={start_date}至{end_date}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # ==================== 1. 构建查询参数（统一处理） ====================
                params_account_flow = []
                params_wsr = []
                where_af = []
                where_wsr = []

                if user_id:
                    where_af.append("af.related_user = %s")
                    params_account_flow.append(user_id)
                    where_wsr.append("wsr.user_id = %s")
                    params_wsr.append(user_id)

                if start_date:
                    where_af.append("DATE(af.created_at) >= %s")
                    params_account_flow.append(start_date)
                    where_wsr.append("DATE(wsr.week_start) >= %s")
                    params_wsr.append(start_date)

                if end_date:
                    where_af.append("DATE(af.created_at) <= %s")
                    params_account_flow.append(end_date)
                    where_wsr.append("DATE(wsr.week_start) <= %s")
                    params_wsr.append(end_date)

                # 为 account_flow 构建 WHERE 子句
                base_where_account = "WHERE account_type IN ('subsidy_points', 'referral_points', 'team_reward_points', 'honor_director', 'true_total_points')"
                if where_af:
                    account_where = base_where_account + " AND " + " AND ".join(where_af)
                else:
                    account_where = base_where_account

                # 为 weekly_subsidy_records 构建 WHERE 子句
                base_where_wsr = "WHERE 1=1"
                if where_wsr:
                    wsr_where = base_where_wsr + " AND " + " AND ".join(where_wsr)
                else:
                    wsr_where = base_where_wsr

                # ==================== 2. 查询 account_flow 数据 ====================
                # 先查询总数
                count_sql = f"SELECT COUNT(*) as total FROM account_flow af {account_where}"
                cur.execute(count_sql, tuple(params_account_flow))
                af_total = cur.fetchone()['total'] or 0

                # 查询明细
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT 
                        af.id as flow_id,
                        af.related_user as user_id,
                        u.name as user_name,
                        af.account_type,
                        af.change_amount,
                        af.balance_after,
                        af.flow_type,
                        af.remark,
                        af.created_at
                    FROM account_flow af
                    JOIN users u ON af.related_user = u.id
                    {account_where}
                    ORDER BY af.created_at DESC
                    LIMIT %s OFFSET %s
                """
                # 确保参数是列表，最后添加分页参数
                af_params = list(params_account_flow) + [page_size, offset]
                cur.execute(detail_sql, tuple(af_params))
                # 强制转换为列表
                af_records = list(cur.fetchall())

                # ==================== 3. 查询 weekly_subsidy_records 补充数据 ====================
                # 查询补充数据源的总数
                count_wsr_sql = f"SELECT COUNT(*) as total FROM weekly_subsidy_records wsr {wsr_where}"
                cur.execute(count_wsr_sql, tuple(params_wsr))
                wsr_total = cur.fetchone()['total'] or 0

                # 如果 account_flow 的记录不足一页，从 wsr 补充
                wsr_records = []
                if len(af_records) < page_size:
                    # 计算在 wsr 中的偏移量
                    wsr_offset = max(0, offset - af_total)
                    wsr_limit = page_size - len(af_records)

                    # 查询 wsr 数据
                    wsr_sql = f"""
                        SELECT 
                            wsr.id as record_id,
                            wsr.user_id,
                            u.name as user_name,
                            wsr.subsidy_amount as change_amount,
                            wsr.week_start as created_at,
                            wsr.points_deducted,
                            wsr.points_before
                        FROM weekly_subsidy_records wsr
                        JOIN users u ON wsr.user_id = u.id
                        {wsr_where}
                        ORDER BY wsr.week_start DESC, wsr.id DESC
                        LIMIT %s OFFSET %s
                    """
                    wsr_params = list(params_wsr) + [wsr_limit, wsr_offset]
                    cur.execute(wsr_sql, tuple(wsr_params))
                    wsr_raw = list(cur.fetchall())

                    # 转换格式：将 wsr 记录转换为与 account_flow 一致的格式
                    for r in wsr_raw:
                        # 查询该用户的当前 subsidy_points 余额
                        cur.execute(
                            "SELECT COALESCE(subsidy_points, 0) as balance FROM users WHERE id = %s",
                            (r['user_id'],)
                        )
                        balance_row = cur.fetchone()
                        current_balance = Decimal(str(balance_row['balance'] if balance_row else 0))

                        # 转换记录格式
                        wsr_records.append({
                            'flow_id': f"wsr_{r['record_id']}",  # 构造唯一ID
                            'user_id': r['user_id'],
                            'user_name': r['user_name'],
                            'account_type': 'subsidy_points',
                            'change_amount': Decimal(str(r['change_amount'] or 0)),  # 补贴金额即点数
                            'balance_after': current_balance,
                            'flow_type': 'income',
                            'remark': f"周补贴发放（扣减积分{r['points_before'] or 0:.4f}分，发放点数{r['change_amount'] or 0:.4f}点）",
                            'created_at': r['created_at']
                        })

                # ==================== 4. 合并并排序结果（确保都是列表） ====================
                # 强制转换为列表（即使 cur.fetchall 返回 tuple）
                all_records = list(af_records) + list(wsr_records)

                # 统一 created_at 类型：将 date 转换为 datetime
                for record in all_records:
                    created_at = record['created_at']
                    if hasattr(created_at, 'year') and hasattr(created_at, 'month') and hasattr(created_at, 'day'):
                        # 如果是 date 类型，转换为 datetime
                        if not hasattr(created_at, 'hour'):
                            from datetime import datetime
                            record['created_at'] = datetime.combine(created_at, datetime.min.time())

                # 按创建时间降序排序
                all_records.sort(key=lambda x: x['created_at'], reverse=True)

                # ==================== 5. 汇总统计（双表合并） ====================
                # account_flow 汇总
                summary_af_sql = f"""
                    SELECT 
                        SUM(CASE WHEN flow_type = 'income' THEN change_amount ELSE 0 END) as total_income,
                        SUM(CASE WHEN flow_type = 'expense' THEN change_amount ELSE 0 END) as total_expense,
                        SUM(CASE WHEN account_type = 'subsidy_points' THEN change_amount ELSE 0 END) as total_subsidy,
                        SUM(CASE WHEN account_type = 'referral_points' THEN change_amount ELSE 0 END) as total_referral,
                        SUM(CASE WHEN account_type = 'team_reward_points' THEN change_amount ELSE 0 END) as total_team,
                        SUM(CASE WHEN account_type = 'honor_director' THEN change_amount ELSE 0 END) as total_unilevel,
                        SUM(CASE WHEN account_type = 'true_total_points' THEN change_amount ELSE 0 END) as total_coupon_deduction
                    FROM account_flow af
                    {account_where}
                """
                cur.execute(summary_af_sql, tuple(params_account_flow))
                af_summary = cur.fetchone()

                # weekly_subsidy_records 汇总（补贴收入）
                summary_wsr_sql = f"""
                    SELECT COALESCE(SUM(subsidy_amount), 0) as total_subsidy
                    FROM weekly_subsidy_records wsr
                    {wsr_where}
                """
                cur.execute(summary_wsr_sql, tuple(params_wsr))
                wsr_summary = cur.fetchone()

                total_count = af_total + wsr_total

                # ==================== 6. 格式化返回数据 ====================
                flow_type_base_mapping = {
                    'subsidy_points': '周补贴收入',
                    'referral_points': '推荐奖励收入',
                    'team_reward_points': '团队奖励收入',
                    'honor_director': '联创星级收入',
                    'true_total_points': '优惠券扣减'  # 默认值
                }

                detailed_records = []
                for r in all_records:
                    account_type = r['account_type']
                    remark = r.get('remark', '')

                    # 智能识别flow_type：如果是true_total_points且remark包含"捐赠"，显示为"用户捐赠"
                    if account_type == 'true_total_points' and '捐赠' in remark:
                        flow_type_label = '用户捐赠'
                        flow_category = '支出'
                        # 确保change_amount为负值
                        change_amount = -abs(float(r['change_amount']))
                    else:
                        flow_type_label = flow_type_base_mapping.get(account_type, account_type)
                        flow_category = '支出' if account_type == 'true_total_points' else '收入'
                        change_amount = float(r['change_amount'])

                    # 确保 created_at 是 datetime 对象
                    created_at = r['created_at']
                    if hasattr(created_at, 'strftime'):
                        created_at_str = created_at.strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        created_at_str = str(created_at)

                    detailed_records.append({
                        'flow_id': str(r['flow_id']),
                        'user_id': r['user_id'],
                        'user_name': r['user_name'],
                        'flow_type': flow_type_label,
                        'flow_category': flow_category,
                        'change_amount': change_amount,
                        'balance_after': float(r['balance_after']) if r['balance_after'] is not None else None,
                        'remark': r['remark'],
                        'created_at': created_at_str
                    })

                # ==================== 7. 获取当前余额快照（单用户查询时） ====================
                current_balances = {}
                if user_id:
                    cur.execute("""
                        SELECT 
                            COALESCE(u.subsidy_points, 0) as subsidy_points,
                            COALESCE(u.referral_points, 0) as referral_points,
                            COALESCE(u.team_reward_points, 0) as team_reward_points,
                            COALESCE(u.points, 0) as unilevel_points,
                            COALESCE(u.true_total_points, 0) as true_total_points
                        FROM users u
                        WHERE id = %s
                    """, (user_id,))
                    balance_row = cur.fetchone()
                    if balance_row:
                        current_balances = {k: float(v) for k, v in balance_row.items()}

                return {
                    'summary': {
                        'report_type': 'all_points_flow_combined',
                        'total_records': total_count,
                        'total_income': float((af_summary['total_income'] or 0) + (wsr_summary['total_subsidy'] or 0)),
                        'total_expense': float(af_summary['total_expense'] or 0),
                        'net_flow': float((af_summary['total_income'] or 0) + (af_summary['total_expense'] or 0) + (
                                    wsr_summary['total_subsidy'] or 0)),
                        'breakdown': {
                            'subsidy_points_income': float(
                                (af_summary.get('total_subsidy', 0) or 0) + (wsr_summary['total_subsidy'] or 0)),
                            'referral_points_income': float(af_summary.get('total_referral', 0) or 0),
                            'team_reward_points_income': float(af_summary.get('total_team', 0) or 0),
                            'unilevel_points_income': float(af_summary.get('total_unilevel', 0) or 0),
                            'coupon_deduction_expense': float(af_summary.get('total_coupon_deduction', 0) or 0)
                        },
                        'current_balances': current_balances
                    },
                    'pagination': {
                        'page': page,
                        'page_size': page_size,
                        'total': total_count,
                        'total_pages': (total_count + page_size - 1) // page_size if total_count > 0 else 1
                    },
                    'data_sources': {
                        'account_flow_records': af_total,
                        'weekly_subsidy_records': wsr_total,
                        'merged_records': len(detailed_records)
                    },
                    'records': detailed_records
                }
    def donate_true_total_points(self, user_id: int, amount: float) -> Dict[str, Any]:
        """
        用户捐赠 true_total_points 到公益基金账户（1:1兑换为资金）

        Args:
            user_id: 用户ID
            amount: 捐赠的点数金额

        Returns:
            dict: 包含捐赠结果和流水ID的字典
        """
        logger.info(f"用户 {user_id} 申请捐赠 true_total_points: {amount:.4f}")

        donation_amount = Decimal(str(amount))
        if donation_amount <= 0:
            raise FinanceException("捐赠金额必须大于0")

        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 1. 查询用户当前 true_total_points 余额
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="id=%s",
                        select_fields=["true_total_points", "name"]
                    )
                    cur.execute(select_sql, (user_id,))
                    user_row = cur.fetchone()

                    if not user_row:
                        raise FinanceException(f"用户不存在: {user_id}")

                    current_balance = Decimal(str(user_row.get('true_total_points', 0) or 0))
                    user_name = user_row.get('name', f'用户{user_id}')

                    # 2. 检查余额是否充足
                    if current_balance < donation_amount:
                        raise FinanceException(
                            f"用户 true_total_points 余额不足，当前余额: {current_balance:.4f}，"
                            f"需要 {donation_amount:.4f}"
                        )

                    # 3. 扣除用户 true_total_points
                    new_balance = current_balance - donation_amount
                    cur.execute(
                        "UPDATE users SET true_total_points = %s WHERE id = %s",
                        (new_balance, user_id)
                    )

                    # 4. 增加公益基金账户余额
                    cur.execute(
                        "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'public_welfare'",
                        (donation_amount,)
                    )

                    # 5. 查询公益基金更新后的余额
                    cur.execute(
                        "SELECT balance FROM finance_accounts WHERE account_type = 'public_welfare'"
                    )
                    welfare_balance_row = cur.fetchone()
                    welfare_balance_after = Decimal(str(welfare_balance_row.get('balance', 0) or 0))

                    # 6. 记录用户点数扣除流水（支出）
                    cur.execute(
                        """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                           flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                        ('true_total_points', user_id, -donation_amount, new_balance, 'expense',
                         f"用户捐赠true_total_points到公益基金 - 捐赠金额¥{donation_amount:.4f}")
                    )
                    expense_flow_id = cur.lastrowid

                    # 7. 记录公益基金账户收入流水
                    cur.execute(
                        """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                           flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                        ('public_welfare', user_id, donation_amount, welfare_balance_after, 'income',
                         f"用户 {user_name}(ID:{user_id}) 捐赠true_total_points - 捐赠金额¥{donation_amount:.4f}")
                    )
                    income_flow_id = cur.lastrowid

                    conn.commit()

                    logger.info(
                        f"用户 {user_id} 捐赠成功: -{donation_amount:.4f} true_total_points, "
                        f"公益基金 +{donation_amount:.4f}"
                    )

                    return {
                        "success": True,
                        "donation_amount": float(donation_amount),
                        "user_balance_after": float(new_balance),
                        "welfare_balance_after": float(welfare_balance_after),
                        "expense_flow_id": expense_flow_id,
                        "income_flow_id": income_flow_id,
                        "message": f"捐赠成功，感谢您的爱心！"
                    }

        except FinanceException:
            raise
        except Exception as e:
            logger.error(f"❌ 用户 {user_id} 捐赠失败: {e}")
            raise FinanceException(f"捐赠失败: {e}")

    def get_platform_flow_summary(
            self,
            start_date: str,
            end_date: str,
            user_id: Optional[int] = None,
            include_detail: bool = True,
            page: int = 1,
            page_size: int = 50
    ) -> Dict[str, Any]:
        """
        平台综合流水报表（整合所有资金池、订单、积分流水）

        整合逻辑：
        1. 查询所有资金池的汇总和明细
        2. 查询订单相关的积分和资金流动
        3. 查询提现申请处理情况
        4. 合并所有流水，按时间倒序排列
        5. 计算总体统计和趋势分析
        """
        logger.info(
            f"生成平台综合流水报表: 日期范围={start_date}至{end_date}, "
            f"用户={user_id or '所有用户'}, 包含明细={include_detail}"
        )

        from datetime import datetime, date
        import itertools

        # ==================== 1. 定义所有资金池类型 ====================
        all_pool_types = [
            'platform_revenue_pool',  # 平台收入池（源头）
            'public_welfare',  # 公益基金
            'subsidy_pool',  # 周补贴池
            'honor_director',  # 荣誉董事分红池
            'company_points',  # 公司积分池
            'maintain_pool',  # 平台维护池
            'director_pool',  # 荣誉董事池
            'shop_pool',  # 社区店池
            'city_pool',  # 城市运营中心池
            'branch_pool',  # 大区分公司池
            'fund_pool'  # 事业发展基金池
        ]

        # ==================== 2. 并行查询所有资金池数据 ====================
        pools_summary = {}
        all_raw_flows = []

        for pool_type in all_pool_types:
            try:
                # 查询资金池汇总（不获取明细，只获取汇总）
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        # 构建WHERE条件
                        where_conditions = [
                            "account_type = %s",
                            "DATE(created_at) BETWEEN %s AND %s"
                        ]
                        params = [pool_type, start_date, end_date]

                        # 只有联创分红池过滤 related_user=NULL
                        if pool_type == 'honor_director':
                            where_conditions.append("related_user IS NULL")

                        # 用户筛选（如果指定了user_id）
                        if user_id:
                            where_conditions.append("related_user = %s")
                            params.append(user_id)

                        where_sql = " AND ".join(where_conditions)

                        # 查询汇总
                        summary_sql = f"""
                            SELECT 
                                COUNT(*) as total_transactions,
                                SUM(CASE WHEN flow_type = 'income' THEN change_amount ELSE 0 END) as total_income,
                                SUM(CASE WHEN flow_type = 'expense' THEN change_amount ELSE 0 END) as total_expense,
                                SUM(change_amount) as net_change
                            FROM account_flow
                            WHERE {where_sql}
                        """
                        cur.execute(summary_sql, tuple(params))
                        summary = cur.fetchone()

                        # 查询期末余额
                        cur.execute(
                            "SELECT balance FROM finance_accounts WHERE account_type = %s",
                            (pool_type,)
                        )
                        balance_row = cur.fetchone()
                        ending_balance = Decimal(str(balance_row['balance'] if balance_row else 0))

                        # 添加到汇总
                        account_name_map = {
                            "platform_revenue_pool": "平台收入池",
                            "public_welfare": "公益基金",
                            "subsidy_pool": "周补贴池",
                            "honor_director": "荣誉董事分红池",
                            "company_points": "公司积分池",
                            "maintain_pool": "平台维护池",
                            "director_pool": "荣誉董事池",
                            "shop_pool": "社区店池",
                            "city_pool": "城市运营中心池",
                            "branch_pool": "大区分公司池",
                            "fund_pool": "事业发展基金池"
                        }

                        pools_summary[pool_type] = {
                            "account_name": account_name_map.get(pool_type, pool_type),
                            "total_transactions": summary['total_transactions'] or 0,
                            "total_income": float(summary['total_income'] or 0),
                            "total_expense": float(summary['total_expense'] or 0),
                            "net_change": float(summary['net_change'] or 0),
                            "ending_balance": float(ending_balance)
                        }

                        # 如果需要明细，查询原始流水
                        if include_detail:
                            # 查询所有流水（不分页，后续统一分页）
                            detail_sql = f"""
                                SELECT 
                                    id as flow_id,
                                    related_user,
                                    change_amount,
                                    balance_after,
                                    flow_type,
                                    remark,
                                    created_at,
                                    %s as account_type
                                FROM account_flow
                                WHERE {where_sql}
                                ORDER BY created_at DESC
                            """
                            cur.execute(detail_sql, tuple([pool_type] + params))
                            flows = cur.fetchall()
                            all_raw_flows.extend(flows)

            except Exception as e:
                logger.warning(f"查询资金池 {pool_type} 数据失败: {e}")
                continue

        # ==================== 3. 查询订单相关流水（积分抵扣、用户支付） ====================
        order_flows = []
        if include_detail:
            try:
                # 使用已有的 get_order_points_flow_report 逻辑
                order_data = self.get_order_points_flow_report(
                    start_date=start_date,
                    end_date=end_date,
                    user_id=user_id,
                    order_no=None,
                    page=1,
                    page_size=10000  # 获取所有记录用于合并
                )

                # 转换订单流水格式，与资金池流水统一
                for record in order_data['records']:
                    # 用户积分获得（收入）
                    if record['user_points_earned'] > 0:
                        order_flows.append({
                            'flow_id': f"order_{record['order_id']}_user_points",
                            'related_user': record['user_id'],
                            'change_amount': Decimal(str(record['user_points_earned'])),
                            'balance_after': None,  # 订单流水不记录余额
                            'flow_type': 'income',
                            'remark': f"订单#{record['order_no']} 用户获得积分{record['user_points_earned']:.4f}",
                            'created_at': datetime.strptime(record['created_at'], "%Y-%m-%d %H:%M:%S"),
                            'account_type': 'order_related'
                        })

                    # 积分抵扣（支出）
                    if record['points_deduction'] > 0:
                        order_flows.append({
                            'flow_id': f"order_{record['order_id']}_points_deduction",
                            'related_user': record['user_id'],
                            'change_amount': -Decimal(str(record['points_deduction'])),
                            'balance_after': None,
                            'flow_type': 'expense',
                            'remark': f"订单#{record['order_no']} 积分抵扣¥{record['points_deduction']:.2f}",
                            'created_at': datetime.strptime(record['created_at'], "%Y-%m-%d %H:%M:%S"),
                            'account_type': 'order_related'
                        })

                    # 平台收入（源头）
                    order_flows.append({
                        'flow_id': f"order_{record['order_id']}_platform_income",
                        'related_user': record['user_id'],
                        'change_amount': Decimal(str(record['net_sales'])),
                        'balance_after': None,
                        'flow_type': 'income',
                        'remark': f"订单#{record['order_no']} 平台收入¥{record['net_sales']:.2f}（总销售额）",
                        'created_at': datetime.strptime(record['created_at'], "%Y-%m-%d %H:%M:%S"),
                        'account_type': 'order_related'
                    })

            except Exception as e:
                logger.warning(f"查询订单相关流水失败: {e}")

        # ==================== 4. 合并所有流水并统一格式 ====================
        all_flows = []

        # 处理资金池流水
        for flow in all_raw_flows:
            try:
                # 确保 created_at 是 datetime 对象
                created_at = flow['created_at']
                if isinstance(created_at, str):
                    created_at = datetime.strptime(created_at, "%Y-%m-%d %H:%M:%S")
                elif isinstance(created_at, date) and not hasattr(created_at, 'hour'):
                    created_at = datetime.combine(created_at, datetime.min.time())

                # 智能识别资金流向类型
                remark = flow['remark']
                flow_category = self._classify_flow_type(
                    account_type=flow['account_type'],
                    flow_type=flow['flow_type'],
                    remark=remark
                )

                all_flows.append({
                    'flow_id': str(flow['flow_id']),
                    'user_id': flow['related_user'],
                    'user_name': self._get_user_name(flow['related_user']),
                    'flow_type': flow_category['type'],
                    'flow_category': flow_category['category'],
                    'change_amount': float(flow['change_amount']),
                    'balance_after': float(flow['balance_after']) if flow['balance_after'] is not None else None,
                    'remark': remark,
                    'created_at': created_at,
                    'source': 'account_flow',
                    'account_type': flow['account_type']
                })
            except Exception as e:
                logger.debug(f"处理流水记录失败: {e}")
                continue

        # 添加订单流水
        all_flows.extend(order_flows)

        # 按时间倒序排序
        all_flows.sort(key=lambda x: x['created_at'], reverse=True)

        # ==================== 5. 分页处理 ====================
        total_records = len(all_flows)
        total_pages = (total_records + page_size - 1) // page_size if total_records > 0 else 1
        offset = (page - 1) * page_size

        paged_flows = all_flows[offset:offset + page_size]

        # ==================== 6. 计算总体统计 ====================
        grand_total_income = sum(
            pool['total_income'] for pool in pools_summary.values()
        )
        grand_total_expense = sum(
            pool['total_expense'] for pool in pools_summary.values()
        )
        grand_net_change = grand_total_income - grand_total_expense

        # 活跃资金池数量（有余额或有交易的）
        active_pools = sum(
            1 for pool in pools_summary.values()
            if pool['ending_balance'] > 0 or pool['total_transactions'] > 0
        )

        # ==================== 7. 组装最终报表 ====================
        result = {
            "summary": {
                "report_type": "platform_flow_summary",
                "query_period": f"{start_date} 至 {end_date}",
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_active_pools": active_pools,
                "grand_total": {
                    "total_income": grand_total_income,
                    "total_expense": grand_total_expense,
                    "net_flow": grand_net_change
                },
                "pools_overview": {
                    "total_balance": sum(pool['ending_balance'] for pool in pools_summary.values()),
                    "total_transactions": sum(pool['total_transactions'] for pool in pools_summary.values())
                }
            },
            "pools_summary": pools_summary,
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total": total_records,
                "total_pages": total_pages,
                "has_next": page < total_pages,
                "has_prev": page > 1
            },
            "flows": paged_flows if include_detail else [],
            "data_sources": [
                "account_flow（资金池流水）",
                "orders + points_log（订单相关流水）"
            ]
        }

        logger.info(
            f"平台综合流水报表生成完成: {total_records}笔交易, "
            f"净流量¥{grand_net_change:.2f}, {active_pools}个活跃资金池"
        )

        return result

    def _classify_flow_type(self, account_type: str, flow_type: str, remark: str) -> Dict[str, str]:
        """
        智能识别流水类型和分类

        返回:
            {
                'type': '用户支付'|'补贴发放'|'分红发放'|'积分抵扣'|'退款回冲'|'提现处理'|'捐赠',
                'category': '收入'|'支出'
            }
        """
        # 默认分类
        category = '收入' if flow_type == 'income' else '支出'

        # 基于account_type识别
        if account_type == 'platform_revenue_pool':
            if '用户支付' in remark:
                flow_type_name = '用户支付'
            elif '退款回冲' in remark:
                flow_type_name = '退款回冲'
            else:
                flow_type_name = '平台收入'
        elif account_type == 'public_welfare':
            flow_type_name = '公益基金'
        elif account_type == 'subsidy_pool':
            flow_type_name = '补贴资金'
        elif account_type == 'honor_director':
            flow_type_name = '联创分红'
        elif account_type == 'company_points':
            flow_type_name = '公司积分'
        elif account_type == 'maintain_pool':
            flow_type_name = '平台维护'
        elif account_type == 'director_pool':
            flow_type_name = '董事分红'
        elif account_type == 'shop_pool':
            flow_type_name = '社区店分润'
        elif account_type == 'city_pool':
            flow_type_name = '城市中心分润'
        elif account_type == 'branch_pool':
            flow_type_name = '大区公司分润'
        elif account_type == 'fund_pool':
            flow_type_name = '发展基金'
        elif account_type == 'true_total_points':
            if '捐赠' in remark:
                flow_type_name = '用户捐赠'
                category = '支出'
            elif '优惠券' in remark:
                flow_type_name = '优惠券发放'
                category = '支出'
            else:
                flow_type_name = '点数调整'
        else:
            flow_type_name = '其他资金变动'

        # 基于remark关键词优化识别
        remark_lower = remark.lower()
        if any(word in remark_lower for word in ['订单', '支付']):
            flow_type_name = '订单交易'
        elif any(word in remark_lower for word in ['补贴', '周补贴']):
            flow_type_name = '周补贴发放'
        elif any(word in remark_lower for word in ['分红', '联创']):
            flow_type_name = '联创分红'
        elif any(word in remark_lower for word in ['提现']):
            flow_type_name = '提现处理'
        elif any(word in remark_lower for word in ['退款']):
            flow_type_name = '订单退款'
        elif any(word in remark_lower for word in ['捐赠']):
            flow_type_name = '公益捐赠'
            category = '支出'

        return {
            'type': flow_type_name,
            'category': category
        }

    def _get_user_name(self, user_id: Optional[int]) -> str:
        """获取用户名称（缓存优化）"""
        if not user_id:
            return "系统"

        # 使用简单的内存缓存（在同一次请求内）
        if not hasattr(self, '_user_name_cache'):
            self._user_name_cache = {}

        if user_id in self._user_name_cache:
            return self._user_name_cache[user_id]

        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT name FROM users WHERE id = %s", (user_id,))
                    row = cur.fetchone()
                    name = row['name'] if row else f"未知用户:{user_id}"
                    self._user_name_cache[user_id] = name
                    return name
        except Exception:
            return f"查询失败:{user_id}"
# ==================== 订单系统财务功能（来自 order/finance.py） ====================

def _build_team_rewards_select(cursor, asset_fields: List[str] = None) -> tuple:
    """
    动态构造 team_rewards 表的 SELECT 语句

    Args:
        cursor: 数据库游标
        asset_fields: 资产字段列表，如果字段不存在则使用默认值 0

    Returns:
        (select_fields_str, existing_columns_set) 元组
        - select_fields_str: 构造的 SELECT 语句（不包含 FROM 子句）
        - existing_columns_set: 已存在的列名集合
    """
    if asset_fields is None:
        asset_fields = ['reward_amount']

    # 获取表结构
    cursor.execute("SHOW COLUMNS FROM team_rewards")
    columns = cursor.fetchall()
    existing_columns = {col['Field'] for col in columns}

    # 构造 SELECT 字段列表
    from core.table_access import _quote_identifier

    select_fields = []
    for col in columns:
        field_name = col['Field']
        select_fields.append(_quote_identifier(field_name))

    # 对于资产字段，如果不存在则添加默认值
    for asset_field in asset_fields:
        if asset_field not in existing_columns:
            select_fields.append(f"0 AS {_quote_identifier(asset_field)}")

    return ", ".join(select_fields), existing_columns


def split_order_funds(order_number: str, total: Decimal, is_vip: bool, cursor=None):
    """订单分账：将订单金额分配给商家和各个资金池

    参数:
        order_number: 订单号
        total: 订单总金额
        is_vip: 是否为会员订单
        cursor: 数据库游标（可选），如果提供则在同一事务中执行
    """
    from core.database import get_conn

    if cursor is not None:
        cur = cursor
        use_external_cursor = True
    else:
        use_external_cursor = False

    try:
        if not use_external_cursor:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    _execute_split(cur, order_number, total)
                    conn.commit()
        else:
            _execute_split(cur, order_number, total)
    except Exception as e:
        if not use_external_cursor:
            raise
        raise


def _execute_split(cur, order_number: str, total: Decimal):
    """执行订单分账逻辑（内部函数）

    参数:
        cur: 数据库游标
        order_number: 订单号
        total: 订单总金额
    """
    # 动态读取配置（优先从 finance_accounts 行中读取 allocation）
    try:
        svc = FinanceService()
        allocs = svc.get_pool_allocations()
        merchant = total * allocs.get('merchant_balance', Decimal('0.8'))
    except Exception:
        merchant = total * Decimal("0.8")

    # 单元级日志：记录订单与初始分配信息
    try:
        logger.debug(f"_execute_split START order={order_number} total={total:.2f} merchant={merchant:.2f}")
        if 'allocs' in locals():
            try:
                ratios_str = {k: str(v) for k, v in allocs.items()}
                logger.debug(f"_execute_split ratios: {ratios_str}")
            except Exception:
                logger.debug("_execute_split: 无法序列化 allocs 比例")
    except Exception:
        pass

    # 更新商家余额（使用 users 表）
    cur.execute(
        "UPDATE users SET merchant_balance=merchant_balance+%s WHERE id=1",
        (merchant,)
    )
    # 记录完整支付链路（100% 收入 → 80% 商家 + 20% 各池）
    svc = FinanceService()

    # ① 平台收入池 +100%
    svc._add_pool_balance(cur, 'platform_revenue_pool', total,
                          f"订单分账: {order_number} 用户支付¥{total:.2f}", None)

    # ② 平台收入池 -80%（商家部分）
    svc._add_pool_balance(cur, 'platform_revenue_pool', -merchant,
                          f"订单分账: {order_number} 商家结算¥{merchant:.2f}", None)

    # ③ 各子池 20% 支出（已在下方 for 循环里记收入，保持不动）
    # 获取商家余额
    select_sql = build_dynamic_select(
        cur,
        "users",
        where_clause="id=1",
        select_fields=["merchant_balance"]
    )
    cur.execute(select_sql)
    merchant_balance_row = cur.fetchone()
    merchant_balance_after = merchant_balance_row["merchant_balance"] if merchant_balance_row else merchant

    # 记录商家流水到 account_flow
    cur.execute(
        """INSERT INTO account_flow (account_type, change_amount, balance_after, flow_type, remark, created_at)
           VALUES (%s, %s, %s, %s, %s, NOW())""",
        ("merchant_balance", merchant, merchant_balance_after, "income", f"订单分账: {order_number}")
    )

    # 按每个子池的配置分配（allocs 中的键是 account_type）
    try:
        # pools_to_assign: keys except merchant_balance
        pools_to_assign = {k: v for k, v in allocs.items() if k != 'merchant_balance'}
    except Exception:
        pools_to_assign = {
            'public_welfare': Decimal('0.01'),
            'maintain_pool': Decimal('0.01'),
            'subsidy_pool': Decimal('0.12'),
            'director_pool': Decimal('0.02'),
            'shop_pool': Decimal('0.01'),
            'city_pool': Decimal('0.01'),
            'branch_pool': Decimal('0.005'),
            'fund_pool': Decimal('0.015')
        }

    for account_type, ratio in pools_to_assign.items():
        if account_type == 'public_welfare':
            continue          # ← 新增：不再重复写公益基金
        try:
            amt = total * ratio
            # 单元级日志：准备分配到指定资金池的金额与比例
            logger.debug(f"_execute_split allocating to {account_type}: ratio={ratio} amt={amt:.2f}")

            # 确保 finance_accounts 中存在该账户类型
            cur.execute(
                "INSERT INTO finance_accounts (account_name, account_type, balance) VALUES (%s, %s, 0) ON DUPLICATE KEY "
                "UPDATE account_name=VALUES(account_name)",
                (account_type, account_type)
            )

            # 更新资金池余额
            cur.execute(
                "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
                (amt, account_type)
            )

            # 获取更新后的余额
            select_sql = build_dynamic_select(
                cur,
                "finance_accounts",
                where_clause="account_type = %s",
                select_fields=["balance"]
            )
            cur.execute(select_sql, (account_type,))
            balance_row = cur.fetchone()
            balance_after = balance_row["balance"] if balance_row else amt

            # 记录流水到 account_flow
            cur.execute(
                """INSERT INTO account_flow (account_type, change_amount, balance_after, flow_type, remark, created_at)
                   VALUES (%s, %s, %s, %s, %s, NOW())""",
                (account_type, amt, balance_after, "income", f"订单分账: {order_number}")
            )
            # 单元级日志：记录分配后余额
            try:
                logger.debug(f"_execute_split {account_type} balance_after={Decimal(str(balance_after)):.2f}")
            except Exception:
                logger.debug(f"_execute_split {account_type} balance_after (unserializable): {balance_after}")
        except Exception as e:
            logger.error(f"分配到池子 {account_type} 时出错: {e}")


def reverse_split_on_refund(order_number: str):
    """退款回冲：撤销订单分账

    参数:
        order_number: 订单号
    """
    from core.database import get_conn

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 从 account_flow 查询商家分得金额
            cur.execute(
                """SELECT SUM(change_amount) AS m FROM account_flow 
                   WHERE account_type='merchant_balance' AND remark LIKE %s AND flow_type='income'""",
                (f"订单分账: {order_number}%",)
            )
            m = cur.fetchone()["m"] or Decimal("0")

            if m > 0:
                # 回冲商家余额
                cur.execute(
                    "UPDATE users SET merchant_balance=merchant_balance-%s WHERE id=1",
                    (m,)
                )

                # 获取回冲后的余额
                select_sql = build_dynamic_select(
                    cur,
                    "users",
                    where_clause="id=1",
                    select_fields=["merchant_balance"]
                )
                cur.execute(select_sql)
                merchant_balance_row = cur.fetchone()
                merchant_balance_after = merchant_balance_row["merchant_balance"] if merchant_balance_row else Decimal("0")

                # 记录回冲流水
                cur.execute(
                    """INSERT INTO account_flow (account_type, change_amount, balance_after, flow_type, remark, created_at)
                       VALUES (%s, %s, %s, %s, %s, NOW())""",
                    ("merchant_balance", -m, merchant_balance_after, "expense", f"退款回冲: {order_number}")
                )

            # 回冲各个资金池
            pool_mapping = {
                "public": "public_welfare",
                "maintain": "maintain_pool",
                "subsidy": "subsidy_pool",
                "director": "director_pool",
                "shop": "shop_pool",
                "city": "city_pool",
                "branch": "branch_pool",
                "fund": "fund_pool"
            }

            for pool_key, account_type in pool_mapping.items():
                # 查询该池子的分账金额
                cur.execute(
                    """SELECT SUM(change_amount) AS amt FROM account_flow 
                       WHERE account_type=%s AND remark LIKE %s AND flow_type='income'""",
                    (account_type, f"订单分账: {order_number}%")
                )
                pool_amt = cur.fetchone()["amt"] or Decimal("0")

                if pool_amt > 0:
                    # 回冲资金池余额
                    cur.execute(
                        "UPDATE finance_accounts SET balance = balance - %s WHERE account_type = %s",
                        (pool_amt, account_type)
                    )

                    # 获取回冲后的余额
                    select_sql = build_dynamic_select(
                        cur,
                        "finance_accounts",
                        where_clause="account_type = %s",
                        select_fields=["balance"]
                    )
                    cur.execute(select_sql, (account_type,))
                    balance_row = cur.fetchone()
                    balance_after = balance_row["balance"] if balance_row else Decimal("0")

                    # 记录回冲流水
                    cur.execute(
                        """INSERT INTO account_flow (account_type, change_amount, balance_after, flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, NOW())""",
                        (account_type, -pool_amt, balance_after, "expense", f"退款回冲: {order_number}")
                    )

            conn.commit()


def get_balance(merchant_id: int = 1):
    """获取商家余额信息

    参数:
        merchant_id: 商家ID，默认为1

    返回:
        dict: 包含 merchant_balance, bank_name, bank_account 的字典
    """
    from core.database import get_conn

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 修改为从 users 表获取 merchant_balance 字段
            cur.execute(
                "SELECT merchant_balance, bank_name, bank_account FROM users WHERE id=%s",
                (merchant_id,)
            )
            row = cur.fetchone()
            if not row:
                # 如果不存在，创建初始记录
                cur.execute(
                    "INSERT INTO users (id, merchant_balance, bank_name, bank_account) VALUES (%s, 0, '', '')",
                    (merchant_id,)
                )
                conn.commit()
                return {"merchant_balance": Decimal("0"), "bank_name": "", "bank_account": ""}
            return row


def bind_bank(bank_name: str, bank_account: str, merchant_id: int = 1):
    """绑定商家银行信息

    参数:
        bank_name: 银行名称
        bank_account: 银行账号
        merchant_id: 商家ID，默认为1
    """
    from core.database import get_conn

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 检查是否存在该商家
            cur.execute("SELECT 1 FROM users WHERE id=%s", (merchant_id,))
            if cur.fetchone():
                # 更新现有记录
                cur.execute(
                    "UPDATE users SET bank_name=%s, bank_account=%s WHERE id=%s",
                    (bank_name, bank_account, merchant_id)
                )
            else:
                # 插入新记录
                cur.execute(
                    "INSERT INTO users (id, bank_name, bank_account) VALUES (%s, %s, %s)",
                    (merchant_id, bank_name, bank_account)
                )
            conn.commit()


def withdraw(amount: Decimal, merchant_id: int = 1) -> bool:
    """商家提现（改用 users.merchant_balance）

    参数:
        amount: 提现金额
        merchant_id: 商家ID，默认为1

    返回:
        bool: 提现是否成功
    """
    from core.database import get_conn

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 1. 查余额
            cur.execute(
                "SELECT merchant_balance FROM users WHERE id=%s",
                (merchant_id,)
            )
            row = cur.fetchone()
            if not row or Decimal(str(row["merchant_balance"] or 0)) < amount:
                return False

            # 2. 扣余额
            cur.execute(
                "UPDATE users SET merchant_balance=merchant_balance-%s WHERE id=%s",
                (amount, merchant_id)
            )
            conn.commit()
            return True


def settle_to_merchant(amount: Decimal, merchant_id: int = 1):
    """结算给商家（订单完成后）

    参数:
        amount: 结算金额
        merchant_id: 商家ID，默认为1
    """
    from core.database import get_conn

    with get_conn() as conn:
        with conn.cursor() as cur:
            # 修改为更新 users 表中的 merchant_balance 字段
            cur.execute(
                "UPDATE users SET merchant_balance=merchant_balance+%s WHERE id=%s",
                (amount, merchant_id)
            )
            conn.commit()


def generate_statement():
    """生成商家日账单"""
    from core.database import get_conn
    from datetime import date, timedelta

    with get_conn() as conn:
        with conn.cursor() as cur:
            yesterday = date.today() - timedelta(days=1)

            # 动态构造 SELECT 语句
            select_sql = build_dynamic_select(
                cur,
                "merchant_statement",
                where_clause="merchant_id=1 AND date<%s",
                order_by="date DESC",
                limit="1"
            )

            # 获取期初余额
            cur.execute(select_sql, (yesterday,))
            row = cur.fetchone()
            opening = Decimal(str(row["closing_balance"])) if row and row.get(
                "closing_balance") is not None else Decimal("0")

            # 获取当日收入（从 account_flow 表查询）
            cur.execute(
                """SELECT SUM(change_amount) AS income FROM account_flow 
                   WHERE account_type='merchant_balance' AND flow_type='income' AND DATE(created_at)=%s""",
                (yesterday,)
            )
            income = cur.fetchone()["income"] or Decimal("0")

            # 当日提现（简化处理，实际应从提现表中查询）
            withdraw_amount = Decimal("0")

            # 计算期末余额
            closing = opening + income - withdraw_amount

            # 插入或更新账单
            cur.execute(
                """INSERT INTO merchant_statement(merchant_id,date,opening_balance,income,withdraw,closing_balance)
                   VALUES(%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE
                   opening_balance=VALUES(opening_balance),income=VALUES(income),withdraw=VALUES(withdraw),closing_balance=VALUES(closing_balance)""",
                (1, yesterday, opening, income, withdraw_amount, closing)
            )
            conn.commit()


