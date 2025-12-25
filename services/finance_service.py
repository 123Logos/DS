# finance_service.py - 已同步database_setup字段变更
# **重要变更说明**：
# 1. 原points字段不再参与积分运算，所有积分逻辑改用member_points（会员积分）
# 2. 所有积分字段类型为DECIMAL(12,4)，需使用Decimal类型处理，禁止int()转换
# 3. merchant_points同步支持小数精度处理

import logging
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
                self._apply_points_discount_v2(cur, user_id, user, points_to_use, total_amount)

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

            # 9. 更新平台资金池（所有商品总金额×80%）
            platform_revenue = final_amount * Decimal('0.80')
            cur.execute(
                "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'platform_revenue_pool'",
                (platform_revenue,)
            )

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

            # 10. 分配其他资金池（公益基金、周补贴池等）
            for purpose, percent in ALLOCATIONS.items():
                if purpose == AllocationKey.PLATFORM_REVENUE_POOL:
                    continue
                alloc_amount = final_amount * percent

                cur.execute(
                    "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
                    (alloc_amount, purpose.value)
                )

                # 记录流水
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
    def _apply_points_discount_v2(self, cur, user_id: int, user, points_to_use: Decimal, amount: Decimal) -> None:
        """积分抵扣处理（v2：接受cursor参数）"""
        user_points = Decimal(str(user.member_points))
        if user_points < points_to_use:
            raise OrderException(f"积分不足，当前{user_points:.4f}分")
        # 已移除：50%限制检查
        # 扣减member_points
        cur.execute(
            "UPDATE users SET member_points = member_points - %s WHERE id = %s AND member_points >= %s",
            (points_to_use, user_id, points_to_use)
        )
        if cur.rowcount == 0:
            # 说明积分不足或被并发消费
            raise OrderException(f"积分不足或并发冲突，无法使用{points_to_use:.4f}分")

        # 更新公司积分池（累计到公司积分）
        cur.execute(
            "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'company_points'",
            (points_to_use,)
        )
        # 记录流水
        cur.execute(
            """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
               flow_type, remark, created_at)
               VALUES (%s, %s, %s, 
                      (SELECT balance FROM finance_accounts WHERE account_type = 'company_points'), 
                      %s, %s, NOW())""",
            ('company_points', user_id, points_to_use, 'income', f"用户{user_id}积分抵扣转入")
        )

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
        platform_revenue = total_amount * Decimal('0.80')

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

        # 分配其他资金池（公益基金、周补贴池等）
        for purpose, percent in ALLOCATIONS.items():
            if purpose == AllocationKey.PLATFORM_REVENUE_POOL:
                continue
            alloc_amount = total_amount * percent

            # 更新池子余额
            cur.execute(
                "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
                (alloc_amount, purpose.value)
            )

            # ==================== 关键修复：为每个池子写入流水 ====================
            cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", (purpose.value,))
            new_balance = Decimal(str(cur.fetchone()['balance'] or 0))

            cur.execute(
                """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                   flow_type, remark, created_at)
                   VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                (purpose.value, PLATFORM_MERCHANT_ID, alloc_amount,
                 new_balance, 'income', f"会员订单#{order_id} {purpose.value}池¥{alloc_amount:.2f}")
            )
            logger.debug(f"池子 {purpose.value} 增加: {alloc_amount:.4f}（已写入流水）")

    # ==================== 创建发放奖励（v2版本） ====================
    def _create_pending_rewards_v2(self, cur, order_id: int, buyer_id: int,
                                   old_level: int, new_level: int,
                                   single_price: Decimal, total_quantity: int) -> None:
        """
        创建推荐和团队奖励（按升级层级逐层发放）

        核心业务规则：
        1. 推荐奖励：用户首次购买会员商品（old_level == 0）时，发放1次
           金额 = 单件会员商品价格 × 0.5
        2. 团队奖励：用户升级时，从L2到new_level每层各发1次
           金额 = 单件会员商品价格 × 0.5
        3. 0→1星升级：不发放团队奖励（因为target_layer=1不满足循环条件）

        Args:
            order_id: 订单ID
            buyer_id: 购买人ID
            old_level: 升级前等级
            new_level: 升级后等级
            single_price: 单件会员商品价格（奖励计算基数）
            total_quantity: 会员商品总数量（用于等级计算）
        """

        # 1. 推荐奖励（仅首次购买时发放一次）
        if old_level == 0:
            cur.execute(
                "SELECT referrer_id FROM user_referrals WHERE user_id = %s",
                (buyer_id,)
            )
            referrer = cur.fetchone()
            if referrer and referrer['referrer_id']:
                reward_amount = single_price * Decimal('0.50')

                # 直接发放到 referral_points 字段
                cur.execute(
                    "UPDATE users SET referral_points = COALESCE(referral_points, 0) + %s WHERE id = %s",
                    (reward_amount, referrer['referrer_id'])
                )

                # 同时更新 true_total_points 字段（记录四种奖励的真实总数）
                cur.execute(
                    "UPDATE users SET true_total_points = true_total_points + %s WHERE id = %s",
                    (reward_amount, referrer['referrer_id'])
                )

                # 记录 account_flow 流水
                cur.execute(
                    "SELECT COALESCE(referral_points, 0) FROM users WHERE id = %s",
                    (referrer['referrer_id'],)
                )
                new_balance = Decimal(str(cur.fetchone()['referral_points'] or 0))

                cur.execute(
                    """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                       flow_type, remark, created_at)
                       VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                    ('referral_points', referrer['referrer_id'], reward_amount,
                     new_balance, 'income', f"推荐奖励立即发放 - 订单#{order_id}，基数¥{single_price:.2f}")
                )

                logger.debug(f"推荐奖励立即发放: 用户{referrer['referrer_id']} +{reward_amount:.2f} referral_points")

        # 2. 团队奖励（按升级层级逐层发放）
        if new_level <= max(old_level, 1):
            logger.debug(f"等级未提升或保持1星，不产生团队奖励")
            return

        # ✅ 为每个升级层级发放团队奖励（L2-L6）
        for target_layer in range(2, new_level + 1):
            current_id = buyer_id

            # 追溯到第target_layer层（沿着推荐链向上找target_layer层）
            for _ in range(target_layer):
                cur.execute(
                    "SELECT referrer_id FROM user_referrals WHERE user_id = %s",
                    (current_id,)
                )
                ref = cur.fetchone()
                if not ref or not ref['referrer_id']:
                    logger.debug(f"第{target_layer}层无推荐人，跳过该层")
                    break
                current_id = ref['referrer_id']

            # 检查该层推荐人等级是否达标
            cur.execute("SELECT member_level FROM users WHERE id = %s", (current_id,))
            row = cur.fetchone()
            referrer_level = row['member_level'] if row else 0

            if referrer_level >= target_layer:
                # ✅ 该层达标，发放奖励
                reward_amount = single_price * Decimal('0.50')

                # 发放到 team_reward_points 字段
                cur.execute(
                    "UPDATE users SET team_reward_points = COALESCE(team_reward_points, 0) + %s WHERE id = %s",
                    (reward_amount, current_id)
                )

                # 更新 true_total_points 字段
                cur.execute(
                    "UPDATE users SET true_total_points = true_total_points + %s WHERE id = %s",
                    (reward_amount, current_id)
                )

                # 记录 account_flow 流水
                cur.execute(
                    "SELECT COALESCE(team_reward_points, 0) FROM users WHERE id = %s",
                    (current_id,)
                )
                new_balance = Decimal(str(cur.fetchone()['team_reward_points'] or 0))

                cur.execute(
                    """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                       flow_type, remark, created_at)
                       VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                    ('team_reward_points', current_id, reward_amount,
                     new_balance, 'income', f"团队L{target_layer}奖励发放 - 订单#{order_id}")
                )

                logger.debug(f"团队奖励立即发放: 用户{current_id} L{target_layer} +{reward_amount:.2f}")
            else:
                logger.debug(f"团队奖励未发放: L{target_layer} 推荐人等级{referrer_level}星不足{target_layer}星")

    def _create_order(self, order_no: str, user_id: int, merchant_id: int,
                      product_id: int, total_amount: Decimal, original_amount: Decimal,
                      points_discount: Decimal, is_member: bool) -> int:
        # 关键修改：字段名 order_number
        result = self.session.execute(
            """INSERT INTO orders (order_number, user_id, merchant_id, total_amount, original_amount, points_discount, is_member_order, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, 'completed')""",
            {
                "order_number": order_no,
                "user_id": user_id,
                "merchant_id": merchant_id,
                "total_amount": total_amount,
                "original_amount": original_amount,
                "points_discount": points_discount,
                "is_member": is_member
            }
        )
        order_id = result.lastrowid

        self.session.execute(
            """INSERT INTO order_items (order_id, product_id, quantity, unit_price, total_price)
                    VALUES (%s, %s, 1, %s, %s)""",
            {
                "order_id": order_id,
                "product_id": product_id,
                "unit_price": original_amount,
                "total_price": original_amount
            }
        )
        return order_id

    # ==================== 关键修改3：member_points积分发放 ====================
    def _allocate_funds_to_pools(self, order_id: int, total_amount: Decimal) -> None:
        platform_revenue = total_amount * Decimal('0.80')
        # 使用 helper 统一处理平台池子余额变更与流水
        self._add_pool_balance('platform_revenue_pool', platform_revenue, f"订单#{order_id} 平台收入")

        for purpose, percent in ALLOCATIONS.items():
            if purpose == AllocationKey.PLATFORM_REVENUE_POOL:
                continue
            alloc_amount = total_amount * percent
            # 统一通过 helper 更新各类池子与记录流水
            self._add_pool_balance(purpose.value, alloc_amount, f"订单#{order_id} 分配到{purpose.value}")
            if purpose == AllocationKey.PUBLIC_WELFARE:
                logger.debug(f"公益基金获得: ¥{alloc_amount}")

    def audit_and_distribute_rewards(self, reward_ids: List[int], approve: bool, auditor: str = 'admin') -> bool:
        """批量审核奖励并发放优惠券"""
        if not reward_ids:
            raise FinanceException("奖励ID列表不能为空")

        placeholders = ','.join(['%s'] * len(reward_ids))

        # ============= 关键修复：移除 try...except，让 FinanceException 直接抛出 =============
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 查询待审核奖励
                cur.execute(
                    f"""SELECT id, user_id, reward_type, amount, order_id, layer
                       FROM pending_rewards 
                       WHERE id IN ({placeholders}) AND status = 'pending'""",
                    reward_ids
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

    # 完整替换 services/finance_service.py 中的 distribute_weekly_subsidy 方法

    def distribute_weekly_subsidy(self) -> bool:
        """
        发放周补贴（增加 subsidy_points 并扣减 member_points）

        关键修复：在扣减积分时同步写入 points_log 流水记录，
        确保积分报表能正确显示周补贴导致的积分支出

        新增：将扣除的积分转入公司积分账户池，并记录资金池流水
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

        # 积分价值 = 补贴池金额 / 总积分，最高0.02
        points_value = pool_balance / total_member_points
        if points_value > MAX_POINTS_VALUE:
            points_value = MAX_POINTS_VALUE

        logger.info(f"补贴池: ¥{pool_balance} | 总积分: {total_member_points} | 积分值: ¥{points_value:.4f}/分")

        total_distributed = Decimal('0')
        total_points_deducted = Decimal('0')  # 新增：统计总扣除积分
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

                        # ====== 核心修复：发放补贴点数 ======
                        new_subsidy_points = current_subsidy_points + points_to_add
                        cur.execute(
                            "UPDATE users SET subsidy_points = %s WHERE id = %s",
                            (new_subsidy_points, user_id)
                        )
                        cur.execute(
                            "UPDATE users SET true_total_points = true_total_points + %s WHERE id = %s",
                            (points_to_add, user_id)
                        )
                        # ====== 核心修复：扣减 member_points 并记录流水 ======
                        # 1. 扣减积分
                        cur.execute(
                            "UPDATE users SET member_points = member_points - %s WHERE id = %s",
                            (member_points, user_id)
                        )

                        # 2. 获取扣减后的余额
                        cur.execute(
                            "SELECT member_points FROM users WHERE id = %s",
                            (user_id,)
                        )
                        new_balance = Decimal(str(cur.fetchone()['member_points'] or 0))

                        # 3. 写入积分扣减流水（type='member' 表示会员积分，change_amount为负值）
                        cur.execute(
                            """INSERT INTO points_log 
                               (user_id, change_amount, balance_after, type, reason, related_order, created_at)
                               VALUES (%s, %s, %s, 'member', %s, NULL, NOW())""",
                            (user_id, -member_points, new_balance, f"周补贴扣减积分")
                        )

                        # ====== 新增：将扣除的积分转入公司积分池 ======
                        # 1. 增加公司积分池余额
                        cur.execute(
                            "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'company_points'",
                            (member_points,)
                        )

                        # 2. 获取更新后的公司积分池余额
                        cur.execute(
                            "SELECT balance FROM finance_accounts WHERE account_type = %s",
                            ('company_points',)
                        )
                        company_balance = Decimal(str(cur.fetchone()['balance'] or 0))

                        # 3. 记录资金池流水
                        cur.execute(
                            """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                               flow_type, remark, created_at)
                               VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                            ('company_points', user_id, member_points, company_balance, 'income',
                             f"周补贴扣除积分转入 - 用户{user_id}扣除{member_points:.4f}分")
                        )

                        # 4. 记录发放历史到 weekly_subsidy_records
                        cur.execute(
                            """INSERT INTO weekly_subsidy_records 
                               (user_id, week_start, subsidy_amount, points_before, points_deducted)
                               VALUES (%s, %s, %s, %s, %s)""",
                            (user_id, today, subsidy_amount, member_points, points_to_add)
                        )

                        total_distributed += subsidy_amount
                        total_points_deducted += member_points  # 累加总扣除积分
                        logger.info(
                            f"用户{user_id}: 发放补贴点数{points_to_add:.4f}, "
                            f"扣减积分{member_points:.4f}, 余额{new_balance:.4f}, "
                            f"转入公司积分池{member_points:.4f}"
                        )

                    # 提交事务
                    conn.commit()

            logger.info(f"周补贴完成: 发放¥{total_distributed:.4f}等值点数，"
                        f"扣除积分{total_points_deducted:.4f}分，涉及{len(users)}个用户")
            return True

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
                cur.execute(f"SELECT {', '.join(select_fields)} FROM withdrawals WHERE id = %s", (withdrawal_id,))
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
        balance_after = self._get_balance_after(cur, account_type, related_user)  # 传cur
        cur.execute(
            """INSERT INTO account_flow (account_id, account_type, related_user, change_amount, balance_after, flow_type, remark, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())""",
            (account_id, account_type, related_user, change_amount, balance_after, flow_type, remark)
        )

    def _add_pool_balance(self, cur, account_type: str, amount: Decimal, remark: str,
                          related_user: Optional[int] = None) -> Decimal:
        """对平台/池子类账户增减余额并记录流水"""
        cur.execute(
            "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
            (amount, account_type)
        )

        cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", (account_type,))
        row = cur.fetchone()
        balance_after = Decimal(str(row['balance'] if row and row['balance'] is not None else 0))

        flow_type = 'income' if amount >= 0 else 'expense'
        self._insert_account_flow(cur, account_type=account_type, related_user=related_user,
                                  change_amount=amount, flow_type=flow_type, remark=remark)
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
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """SELECT id, coupon_type, amount, status, valid_from, valid_to, used_at, created_at
                       FROM coupons WHERE user_id = %s AND status = %s
                       ORDER BY created_at DESC""",
                    (user_id, status)
                )
                coupons = cur.fetchall()
                return [{
                    "id": c['id'],
                    "coupon_type": c['coupon_type'],
                    "amount": float(c['amount']),
                    "status": c['status'],
                    "valid_from": c['valid_from'].strftime("%Y-%m-%d"),
                    "valid_to": c['valid_to'].strftime("%Y-%m-%d"),
                    "used_at": c['used_at'].strftime("%Y-%m-%d %H:%M:%S") if c['used_at'] else None,
                    "created_at": c['created_at'].strftime("%Y-%m-%d %H:%M:%S")
                } for c in coupons]

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
                select_sql = f"SELECT {', '.join(select_fields)} FROM {_quote_identifier('finance_accounts')}"
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

                sql = f"SELECT {', '.join(select_parts)} FROM {_quote_identifier('account_flow')} ORDER BY created_at DESC LIMIT %s"
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

    def distribute_unilevel_dividend(self) -> bool:
        """发放联创星级分红（手动触发）"""
        logger.info("联创星级分红发放开始")

        # ============= 关键修改：事务外查询数据 =============
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT uu.user_id, uu.level, u.name, u.member_level
                    FROM user_unilevel uu
                    JOIN users u ON uu.user_id = u.id
                    WHERE uu.level IN (1, 2, 3)
                """)
                unilevel_users = cur.fetchall()

        if not unilevel_users:
            logger.warning("没有符合条件的联创用户")
            return False

        total_weight = sum(Decimal(str(user['level'])) for user in unilevel_users)
        pool_balance = self.get_account_balance('honor_director')

        if pool_balance <= 0:
            logger.warning(f"联创分红资金池余额不足: ¥{pool_balance}")
            return False

        # ============= 关键修改：使用 get_conn() 替代 self.session =============
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    total_distributed = Decimal('0')

                    for user in unilevel_users:
                        user_id = user['user_id']
                        weight = Decimal(str(user['level']))

                        dividend_amount = pool_balance * weight / total_weight
                        points_to_add = dividend_amount

                        cur.execute(
                            "UPDATE users SET points = COALESCE(points, 0) + %s WHERE id = %s",
                            (points_to_add, user_id)
                        )
                        cur.execute(
                            "UPDATE users SET true_total_points = true_total_points + %s WHERE id = %s",
                            (points_to_add, user_id)
                        )
                        # 记录流水
                        cur.execute(
                            """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, flow_type, remark, created_at)
                               VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                            ('honor_director', user_id, points_to_add, 0, 'income',
                             f"联创{weight}星级分红（权重{weight}/{total_weight}）")
                        )

                        total_distributed += points_to_add
                        logger.debug(f"用户{user_id}获得联创分红点数: {points_to_add:.4f}")

                    conn.commit()

            logger.info(f"联创星级分红完成: 共{len(unilevel_users)}人，发放点数{total_distributed:.4f}")
            return True

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
                sql = f"""SELECT {', '.join(select_fields)}
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
                                   valid_days: int = COUPON_VALID_DAYS) -> int:
        """直接发放优惠券给用户（需扣除 true_total_points）"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # ========== 新增：检查 true_total_points 余额 ==========
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

                    # ========== 原有逻辑：发放优惠券 ==========
                    today = datetime.now().date()
                    valid_to = today + timedelta(days=valid_days)

                    cur.execute(
                        """INSERT INTO coupons (user_id, coupon_type, amount, valid_from, valid_to, status)
                           VALUES (%s, %s, %s, %s, %s, 'unused')""",
                        (user_id, coupon_type, coupon_amount, today, valid_to)
                    )
                    coupon_id = cur.lastrowid

                    # ========== 新增：扣除 true_total_points ==========
                    new_balance = current_balance - coupon_amount
                    cur.execute(
                        "UPDATE users SET true_total_points = %s WHERE id = %s",
                        (new_balance, user_id)
                    )

                    # ========== 新增：记录扣除流水 ==========
                    cur.execute(
                        """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, 
                           flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                        ('true_total_points', user_id, -coupon_amount, new_balance, 'expense',
                         f"发放优惠券扣除 - 优惠券#{coupon_id}，金额¥{coupon_amount:.2f}")
                    )

                    conn.commit()

                    logger.debug(f"发放优惠券给用户{user_id}: ID={coupon_id}, 金额¥{coupon_amount:.2f}, "
                                 f"扣除 true_total_points {coupon_amount:.4f}")
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
                            "points_issued": float(r['points_issued']),
                            "current_points_balance": float(r['current_points'] or 0),
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
                        "total_referral_points": float(summary.get('total_referral_points', 0) or 0),
                        "total_team_points": float(summary.get('total_team_points', 0) or 0)
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
                            "points_issued": float(r['points_issued']),
                            "current_points_balance": float(r['current_points'] or 0),
                            "remark": r['remark'],
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "points_field": r['account_type'],
                            "status": "已自动发放"
                        } for r in records
                    ]
                }

    # ==================== 4. 优惠券使用（消失）- 增强流水记录 ====================
    def use_coupon(self, coupon_id: int, user_id: int) -> bool:
        """使用优惠券，使其状态变为已使用，并记录流水"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 使用条件更新原子性标记优惠券为已使用，避免长事务锁等待
                    today = datetime.now().date()
                    cur.execute(
                        """UPDATE coupons SET status = 'used', used_at = NOW()
                           WHERE id = %s AND user_id = %s AND status = 'unused' AND valid_from <= %s AND valid_to >= %s""",
                        (coupon_id, user_id, today, today)
                    )
                    if cur.rowcount == 0:
                        raise FinanceException("优惠券不存在、已使用或不在有效期内")

                    # 查询已被标记的优惠券金额
                    cur.execute("SELECT amount FROM coupons WHERE id = %s", (coupon_id,))
                    coupon = cur.fetchone()
                    coupon_amount = Decimal(str(coupon['amount'] or 0))

                    # 更新优惠券状态为已使用（已在条件更新中完成）
                    cur.execute(
                        "UPDATE coupons SET status = 'used', used_at = NOW() WHERE id = %s",
                        (coupon_id,)
                    )

                    # 记录优惠券使用流水（在当前事务的同一 cursor 上执行，保证原子性）
                    # 获取对应账户的当前余额（finance_accounts 表）
                    cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", ('coupon',))
                    row = cur.fetchone()
                    balance_after = Decimal(str(row.get('balance') or 0)) if row else Decimal('0')
                    cur.execute(
                        """INSERT INTO account_flow (account_id, account_type, related_user, change_amount, balance_after, flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())""",
                        (None, 'coupon', user_id, Decimal('0'), balance_after, 'expense', f"用户使用优惠券 - 优惠券#{coupon_id}，抵扣金额¥{coupon_amount:.2f}")
                    )

                    # 记录平台获得优惠券抵扣额（在当前事务内使用同一 cursor）
                    cur.execute("SELECT balance FROM finance_accounts WHERE account_type = %s", ('coupon_revenue',))
                    row2 = cur.fetchone()
                    balance_after2 = Decimal(str(row2.get('balance') or 0)) if row2 else Decimal('0')
                    cur.execute(
                        """INSERT INTO account_flow (account_id, account_type, related_user, change_amount, balance_after, flow_type, remark, created_at)
                           VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())""",
                        (None, 'coupon_revenue', PLATFORM_MERCHANT_ID, coupon_amount, balance_after2, 'income', f"优惠券抵扣额记录 - 优惠券#{coupon_id}，用户{user_id}使用，金额¥{coupon_amount:.2f}")
                    )

                    conn.commit()
                    logger.debug(f"用户{user_id}使用优惠券{coupon_id}:¥{coupon_amount}成功")
                    return True

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
    # ==================== 平台资金池变动报表（中优先级） ====================
    def get_pool_flow_report(self, account_type: str,
                             start_date: str, end_date: str,
                             page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """
        平台资金池变动明细报表

        查询指定资金池的每一笔流水，包括收入、支出和余额变化

        Args:
            account_type: 资金池类型（如 'public_welfare', 'subsidy_pool' 等）
            start_date: 开始日期 yyyy-MM-dd
            end_date: 结束日期 yyyy-MM-dd
            page: 页码
            page_size: 每页条数

        Returns:
            包含汇总统计和流水明细的报表数据
        """
        logger.info(f"生成资金池流水报表: 账户={account_type}, 日期范围={start_date}至{end_date}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 汇总统计
                cur.execute("""
                    SELECT 
                        COUNT(*) as total_transactions,
                        SUM(CASE WHEN flow_type = 'income' THEN change_amount ELSE 0 END) as total_income,
                        SUM(CASE WHEN flow_type = 'expense' THEN change_amount ELSE 0 END) as total_expense,
                        MAX(balance_after) as ending_balance
                    FROM account_flow
                    WHERE account_type = %s AND DATE(created_at) BETWEEN %s AND %s
                """, (account_type, start_date, end_date))

                summary = cur.fetchone()

                # 总记录数
                cur.execute("""
                    SELECT COUNT(*) as total 
                    FROM account_flow
                    WHERE account_type = %s AND DATE(created_at) BETWEEN %s AND %s
                """, (account_type, start_date, end_date))
                total_count = cur.fetchone()['total'] or 0

                # 明细查询
                offset = (page - 1) * page_size
                cur.execute("""
                    SELECT 
                        id, related_user, change_amount, balance_after, 
                        flow_type, remark, created_at
                    FROM account_flow
                    WHERE account_type = %s AND DATE(created_at) BETWEEN %s AND %s
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """, (account_type, start_date, end_date, page_size, offset))

                records = cur.fetchall()

                # 获取用户名称
                def get_user_name(uid):
                    if not uid:
                        return "系统"
                    try:
                        cur.execute("SELECT name FROM users WHERE id = %s", (uid,))
                        row = cur.fetchone()
                        return row['name'] if row else "未知用户"
                    except:
                        return f"未知用户:{uid}"

                return {
                    "summary": {
                        "report_type": "pool_flow",
                        "account_type": account_type,
                        "account_name": {
                            "public_welfare": "公益基金",
                            "subsidy_pool": "周补贴池",
                            "honor_director": "荣誉董事分红池",
                            "company_points": "公司积分池",
                            "platform_revenue_pool": "平台收入池"
                        }.get(account_type, account_type),
                        "total_transactions": summary['total_transactions'] or 0,
                        "total_income": float(summary['total_income'] or 0),
                        "total_expense": float(summary['total_expense'] or 0),
                        "net_change": float((summary['total_income'] or 0) - (summary['total_expense'] or 0)),
                        "ending_balance": float(summary['ending_balance'] or 0)
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
                            "change_amount": float(r['change_amount']),
                            "balance_after": float(r['balance_after']) if r['balance_after'] else None,
                            "flow_type": r['flow_type'],
                            "remark": r['remark'],
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S")
                        } for r in records
                    ]
                }
    # ==================== 联创星级点数流水报表 ====================
    def get_unilevel_points_flow_report(self, user_id: Optional[int] = None,
                                        level: Optional[int] = None,
                                        start_date: Optional[str] = None,
                                        end_date: Optional[str] = None,
                                        page: int = 1,
                                        page_size: int = 20) -> Dict[str, Any]:
        """
        联创星级点数流水报表

        查询联创会员的星级分红发放记录，支持按用户、星级、日期筛选

        Args:
            user_id: 用户ID（可选）
            level: 星级（1-3，可选）
            start_date: 开始日期 yyyy-MM-dd（可选）
            end_date: 结束日期 yyyy-MM-dd（可选）
            page: 页码
            page_size: 每页条数

        Returns:
            包含汇总、分页和明细的字典
        """
        logger.info(f"生成联创星级点数流水报表: 用户={user_id}, 星级={level}, 日期范围={start_date}至{end_date}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建WHERE条件
                where_conditions = []
                params = []

                if user_id:
                    where_conditions.append("d.user_id = %s")
                    params.append(user_id)

                if level:
                    where_conditions.append("u.level = %s")
                    params.append(level)

                if start_date:
                    where_conditions.append("DATE(d.created_at) >= %s")
                    params.append(start_date)

                if end_date:
                    where_conditions.append("DATE(d.created_at) <= %s")
                    params.append(end_date)

                where_sql = " AND ".join(where_conditions) if where_conditions else "1=1"

                # 总记录数查询
                count_sql = f"""
                    SELECT COUNT(*) as total 
                    FROM director_dividends d
                    JOIN user_unilevel u ON d.user_id = u.user_id
                    WHERE {where_sql}
                """
                cur.execute(count_sql, tuple(params))
                total_count = cur.fetchone()['total'] or 0

                # 明细查询
                offset = (page - 1) * page_size
                detail_sql = f"""
                    SELECT d.user_id, us.name as user_name, u.level as unilevel_level,
                           d.dividend_amount, d.new_sales, d.weight, d.period_date, d.created_at
                    FROM director_dividends d
                    JOIN user_unilevel u ON d.user_id = u.user_id
                    JOIN users us ON d.user_id = us.id
                    WHERE {where_sql}
                    ORDER BY d.period_date DESC, d.user_id
                    LIMIT %s OFFSET %s
                """
                params.extend([page_size, offset])
                cur.execute(detail_sql, tuple(params))
                records = cur.fetchall()

                # 汇总统计
                summary_sql = f"""
                    SELECT COUNT(DISTINCT d.user_id) as total_users,
                           SUM(d.dividend_amount) as total_dividend_amount,
                           SUM(d.new_sales) as total_new_sales
                    FROM director_dividends d
                    JOIN user_unilevel u ON d.user_id = u.user_id
                    WHERE {where_sql}
                """
                cur.execute(summary_sql, tuple(params[:-2]))
                summary = cur.fetchone()

                return {
                    "summary": {
                        "report_type": "unilevel_points_flow",
                        "total_users": summary['total_users'] or 0,
                        "total_dividend_amount": float(summary['total_dividend_amount'] or 0),
                        "total_new_sales": float(summary['total_new_sales'] or 0)
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
                            "unilevel_level": r['unilevel_level'],
                            "level_name": f"{r['unilevel_level']}星级联创",
                            "points": float(r['dividend_amount'] or 0),
                            "new_sales": float(r['new_sales'] or 0),
                            "weight": r['weight'] or 1,
                            "period_date": r['period_date'].strftime("%Y-%m-%d"),
                            "created_at": r['created_at'].strftime("%Y-%m-%d %H:%M:%S"),
                            "remark": f"{r['unilevel_level']}星级联创分红，权重{r['weight']}"
                        } for r in records
                    ]
                }

    def clear_fund_pools(self, pool_types: List[str]) -> Dict[str, Any]:
        """清空指定的资金池"""
        logger.info(f"开始清空资金池: {pool_types}")

        if not pool_types:
            raise FinanceException("必须指定要清空的资金池类型")

        # 验证所有池子类型是否有效
        valid_pools = [key.value for key in AllocationKey]
        for pool_type in pool_types:
            if pool_type not in valid_pools:
                raise FinanceException(f"无效的资金池类型: {pool_type}")

        # ============= 关键修改：事务外查询余额 =============
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

        # ============= 关键修改：使用 get_conn() 替代 self.session =============
        cleared_pools = []
        total_cleared = Decimal('0')

        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    for pool_info in pools_to_clear:
                        pool_type = pool_info["account_type"]
                        account_name = pool_info["account_name"]
                        current_balance = pool_info["balance"]

                        # 执行清空操作
                        cur.execute(
                            "UPDATE finance_accounts SET balance = 0 WHERE account_type = %s",
                            (pool_type,)
                        )

                        # 记录流水
                        cur.execute(
                            """INSERT INTO account_flow (account_type, related_user, change_amount, balance_after, flow_type, remark, created_at)
                               VALUES (%s, %s, %s, %s, %s, %s, NOW())""",
                            (pool_type, None, -current_balance, 0, 'expense', "手动清空资金池")
                        )

                        cleared_pools.append({
                            "account_type": pool_type,
                            "account_name": account_name,
                            "amount_cleared": float(current_balance),
                            "previous_balance": float(current_balance)
                        })
                        total_cleared += current_balance

                        logger.info(f"已清空资金池 {pool_type}: ¥{current_balance:.2f}")

                    # 提交事务
                    conn.commit()

            logger.info(f"资金池清空完成: 共清空 {len(cleared_pools)} 个，总计 ¥{total_cleared:.2f}")

            return {
                "cleared_pools": cleared_pools,
                "total_cleared": float(total_cleared)
            }

        except Exception as e:
            logger.error(f"清空资金池失败: {e}", exc_info=True)
            raise

    # services/finance_service.py

    # ... 在 clear_fund_pools 方法之后添加 ...

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
        """周补贴预览报表（全用户）

        查询所有用户在指定周的积分余额和预计可获得的周补贴优惠券金额
        支持分页返回

        Args:
            year: 年份，如2025
            week: 周数，1-53
            page: 页码
            page_size: 每页条数

        Returns:
            包含汇总统计、分页信息和用户明细列表的字典
        """
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

                # 3. 计算积分价值
                if total_points <= 0:
                    points_value = Decimal('0')
                else:
                    points_value = pool_balance / total_points
                    if points_value > MAX_POINTS_VALUE:
                        points_value = MAX_POINTS_VALUE

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
                        "estimated_coupon_amount": float(estimated_coupon),
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
                        "max_points_value_applied": points_value >= MAX_POINTS_VALUE
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

    # 替换 services/finance_service.py 中的 get_order_points_flow_report 方法

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
                order_ids = [str(order['order_id']) for order in orders]
                order_addons_map = {}

                if order_ids:
                    placeholders = ','.join(['%s'] * len(order_ids))

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
                    """, tuple(order_ids))

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
                    """, tuple(order_ids))
                    total_user_points = cur.fetchone()['total_user_points'] or 0

                    # 总抵扣积分
                    cur.execute(f"""
                        SELECT SUM(ABS(change_amount)) as total_deducted_points
                        FROM points_log
                        WHERE type = 'member' AND change_amount < 0
                          AND related_order IN ({placeholders})
                    """, tuple(order_ids))
                    total_deducted_points = cur.fetchone()['total_deducted_points'] or 0

                    # 总商户积分
                    cur.execute(f"""
                        SELECT SUM(change_amount) as total_merchant_points
                        FROM points_log
                        WHERE type = 'merchant'
                          AND related_order IN ({placeholders})
                    """, tuple(order_ids))
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
        查询所有点数类型的流水报表（周补贴、推荐奖励、团队奖励、联创星级）

        关键变更：显示所有用户，包括没有点数余额和流水记录的用户（显示为0）

        Args:
            user_id: 用户ID（可选，不传则查询所有用户）

        Returns:
            包含各点数类型统计和明细的字典
        """
        logger.info(f"生成所有点数流水报表: 用户={user_id or '所有用户'}")

        with get_conn() as conn:
            with conn.cursor() as cur:
                # 构建用户查询条件
                user_where = "WHERE u.id = %s" if user_id else ""
                user_params = [user_id] if user_id else []

                # 关键变更：查询所有用户（移除HAVING子句，不再过滤无点数的用户）
                sql = f"""
                    SELECT u.id, u.name,
                        COALESCE(u.subsidy_points, 0) as subsidy_balance,
                        COALESCE(u.referral_points, 0) as referral_balance,
                        COALESCE(u.team_reward_points, 0) as team_balance,
                        COALESCE(u.points, 0) as unilevel_balance
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

                # 批量查询用户的累计收入（从account_flow表）
                user_ids = [str(u['id']) for u in users]
                income_map = {}

                if user_ids:
                    placeholders = ','.join(['%s'] * len(user_ids))
                    cur.execute(f"""
                        SELECT 
                            related_user,
                            account_type,
                            SUM(change_amount) as total_income
                        FROM account_flow
                        WHERE related_user IN ({placeholders})
                            AND account_type IN ('subsidy_points', 'referral_points', 'team_reward_points', 'honor_director')
                            AND flow_type = 'income'
                        GROUP BY related_user, account_type
                    """, tuple(user_ids))

                    income_records = cur.fetchall()

                    # 构建收入映射（用户ID -> {点数类型: 累计收入}）
                    for record in income_records:
                        uid = record['related_user']
                        if uid not in income_map:
                            income_map[uid] = {}
                        income_map[uid][record['account_type']] = Decimal(str(record['total_income'] or 0))

                # 组装结果（所有用户都包含，没有收入记录的用户显示为0）
                result = []
                for user in users:
                    uid = user['id']
                    user_income = income_map.get(uid, {})  # 无记录则返回空字典

                    # 各点数类型的累计收入（默认为0）
                    subsidy_income = user_income.get('subsidy_points', Decimal('0'))
                    referral_income = user_income.get('referral_points', Decimal('0'))
                    team_income = user_income.get('team_reward_points', Decimal('0'))
                    unilevel_income = user_income.get('honor_director', Decimal('0'))

                    # 当前余额（从users表获取，COALESCE已处理NULL）
                    subsidy_balance = Decimal(str(user['subsidy_balance']))
                    referral_balance = Decimal(str(user['referral_balance']))
                    team_balance = Decimal(str(user['team_balance']))
                    unilevel_balance = Decimal(str(user['unilevel_balance']))

                    # 计算消耗（当前业务无消耗场景，后续有消耗逻辑时可调整）
                    # 消耗 = 累计收入 - 当前余额
                    subsidy_expense = max(Decimal('0'), subsidy_income - subsidy_balance)
                    referral_expense = max(Decimal('0'), referral_income - referral_balance)
                    team_expense = max(Decimal('0'), team_income - team_balance)
                    unilevel_expense = max(Decimal('0'), unilevel_income - unilevel_balance)

                    result.append({
                        "user_id": uid,
                        "user_name": user['name'],
                        "points_summary": {
                            "subsidy_points": {
                                "current_balance": float(subsidy_balance),
                                "total_earned": float(subsidy_income),
                                "total_used": float(subsidy_expense),
                                "remark": "周补贴专用点数"
                            },
                            "referral_points": {
                                "current_balance": float(referral_balance),
                                "total_earned": float(referral_income),
                                "total_used": float(referral_expense),
                                "remark": "推荐奖励专用点数"
                            },
                            "team_reward_points": {
                                "current_balance": float(team_balance),
                                "total_earned": float(team_income),
                                "total_used": float(team_expense),
                                "remark": "团队奖励专用点数"
                            },
                            "unilevel_points": {
                                "current_balance": float(unilevel_balance),
                                "total_earned": float(unilevel_income),
                                "total_used": float(unilevel_expense),
                                "remark": "联创星级分红专用点数"
                            }
                        },
                        "grand_total": {
                            "total_balance": float(
                                subsidy_balance + referral_balance + team_balance + unilevel_balance),
                            "total_earned": float(subsidy_income + referral_income + team_income + unilevel_income),
                            "total_used": float(subsidy_expense + referral_expense + team_expense + unilevel_expense)
                        }
                    })

                return {
                    "summary": {
                        "total_users": len(result),
                        "report_type": "all_points_flow",
                        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
                user_ids = [str(u['id']) for u in users]
                income_map = {}
                if user_ids:
                    placeholders = ','.join(['%s'] * len(user_ids))
                    cur.execute(f"""
                        SELECT related_user, COALESCE(SUM(change_amount), 0) as total_income
                        FROM account_flow
                        WHERE related_user IN ({placeholders})
                            AND account_type = 'subsidy_points' AND flow_type = 'income'
                        GROUP BY related_user
                    """, tuple(user_ids))

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
                user_ids = [str(u['id']) for u in users]
                income_map = {}
                if user_ids:
                    placeholders = ','.join(['%s'] * len(user_ids))
                    cur.execute(f"""
                        SELECT related_user, COALESCE(SUM(change_amount), 0) as total_income
                        FROM account_flow
                        WHERE related_user IN ({placeholders})
                            AND account_type = 'honor_director' AND flow_type = 'income'
                        GROUP BY related_user
                    """, tuple(user_ids))

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
                user_ids = [str(u['id']) for u in users]
                income_map = {}

                if user_ids:
                    placeholders = ','.join(['%s'] * len(user_ids))
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
                    """, tuple(user_ids))

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
                flow_type_mapping = {
                    'subsidy_points': '周补贴收入',
                    'referral_points': '推荐奖励收入',
                    'team_reward_points': '团队奖励收入',
                    'honor_director': '联创星级收入',
                    'true_total_points': '优惠券扣减'
                }

                detailed_records = []
                for r in all_records:
                    account_type = r['account_type']
                    flow_type_label = flow_type_mapping.get(account_type, account_type)

                    flow_category = '支出' if account_type == 'true_total_points' else '收入'
                    change_amount = float(r['change_amount'])
                    if account_type == 'true_total_points':
                        change_amount = -abs(change_amount)  # 确保是负值

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
    # 商家分得 80%
    merchant = total * Decimal("0.8")

    # 更新商家余额（使用 users 表）
    cur.execute(
        "UPDATE users SET merchant_balance=merchant_balance+%s WHERE id=1",
        (merchant,)
    )

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

    # 平台分得 20%，再分配到各个资金池
    pool_total = total * Decimal("0.2")
    # 池子类型到账户类型的映射
    pool_mapping = {
        "public": "public_welfare",  # 公益基金
        "maintain": "maintain_pool",  # 平台维护
        "subsidy": "subsidy_pool",  # 周补贴池
        "director": "director_pool",  # 荣誉董事分红
        "shop": "shop_pool",  # 社区店
        "city": "city_pool",  # 城市运营中心
        "branch": "branch_pool",  # 大区分公司
        "fund": "fund_pool"  # 事业发展基金
    }
    pools = {
        "public": 0.01,  # 公益基金
        "maintain": 0.01,  # 平台维护
        "subsidy": 0.12,  # 周补贴池
        "director": 0.02,  # 荣誉董事分红
        "shop": 0.01,  # 社区店
        "city": 0.01,  # 城市运营中心
        "branch": 0.005,  # 大区分公司
        "fund": 0.015  # 事业发展基金
    }

    for pool_key, pool_ratio in pools.items():
        amt = pool_total * Decimal(str(pool_ratio))
        account_type = pool_mapping[pool_key]

        # 确保 finance_accounts 中存在该账户类型
        cur.execute(
            "INSERT INTO finance_accounts (account_name, account_type, balance) VALUES (%s, %s, 0) ON DUPLICATE KEY "
            "UPDATE account_name=VALUES(account_name)",
            (pool_key, account_type)
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
