# finance_service.py - 已同步database_setup字段变更
# **重要变更说明**：
# 1. 原points字段不再参与积分运算，所有积分逻辑改用member_points（会员积分）
# 2. 所有积分字段类型为DECIMAL(12,4)，需使用Decimal类型处理，禁止int()转换
# 3. merchant_points同步支持小数精度处理

import logging
from decimal import Decimal
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
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
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) as count FROM orders WHERE user_id = %s AND is_member_order = 1 AND created_at >= NOW() - INTERVAL 24 HOUR AND status != 'refunded'",
                    (user_id,)
                )
                row = cur.fetchone()
                return row['count'] < MAX_PURCHASE_PER_DAY if row else False

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

    # ==================== 关键修改1：积分字段从points改为member_points ====================
    def settle_order(self, order_no: str, user_id: int, product_id: int, quantity: int = 1,
                     points_to_use: Decimal = Decimal('0')) -> int:
        logger.debug(f"订单结算开始: {order_no}")
        try:
            with self.session.begin():
                # 关键修改：从 product_skus 表获取价格，兼容旧数据
                result = self.session.execute(
                    """SELECT p.is_member_product, p.user_id, 
                              COALESCE(ps.price, p.price) as price
                       FROM products p
                       LEFT JOIN product_skus ps ON p.id = ps.product_id
                       WHERE p.id = %s AND p.status = 1
                       LIMIT 1""",
                    {"product_id": product_id}
                )
                product = result.fetchone()
                if not product or product['price'] is None:
                    raise OrderException(f"商品不存在、已下架或无价格信息: {product_id}")

                merchant_id = product['user_id']  # 关键修改：字段名改为 user_id
                if merchant_id != PLATFORM_MERCHANT_ID:
                    result = self.session.execute(
                        "SELECT id FROM users WHERE id = %s",
                        {"merchant_id": merchant_id}
                    )
                    if not result.fetchone():
                        raise OrderException(f"商家不存在: {merchant_id}")

                if product['is_member_product'] and not self.check_purchase_limit(user_id):
                    raise OrderException("24小时内购买会员商品超过限制（最多2份）")

                unit_price = Decimal(str(product['price']))
                original_amount = unit_price * quantity

                # 使用动态表访问获取用户信息，使用 FOR UPDATE 锁定行
                # 关键修改：查询member_points而非points，使用Decimal类型
                with get_conn() as conn:
                    with conn.cursor() as cur:
                        select_sql = build_dynamic_select(
                            cur,
                            "users",
                            where_clause="id=%s",
                            select_fields=["member_level", "member_points"]  # 修改：member_points替代points
                        )
                        select_sql += " FOR UPDATE"
                        cur.execute(select_sql, (user_id,))
                        row = cur.fetchone()
                        if not row:
                            raise OrderException(f"用户不存在: {user_id}")
                        # 创建类似的对象以保持兼容性
                        user = type('obj', (object,), {
                            'member_level': row.get('member_level', 0) or 0,
                            'member_points': Decimal(str(row.get('member_points', 0) or 0))  # 修改：DECIMAL类型
                        })()

                points_discount = Decimal('0')
                final_amount = original_amount

                # 关键修改：使用member_points进行积分抵扣计算
                if not product['is_member_product'] and points_to_use > Decimal('0'):
                    self._apply_points_discount(user_id, user, points_to_use, original_amount)
                    points_discount = points_to_use * POINTS_DISCOUNT_RATE
                    final_amount = original_amount - points_discount
                    logger.debug(f"积分抵扣: {points_to_use:.4f}分 = ¥{points_discount:.4f}")

                order_id = self._create_order(
                    order_no, user_id, merchant_id, product_id,
                    final_amount, original_amount, points_discount, product['is_member_product']
                )

                if product['is_member_product']:
                    self._process_member_order(order_id, user_id, user, unit_price, quantity)
                else:
                    self._process_normal_order(order_id, user_id, merchant_id, final_amount, user.member_level)

            logger.debug(f"订单结算成功: ID={order_id}")
            return order_id
        except Exception as e:
            logger.error(f"订单结算失败: {e}")
            raise

    # ==================== 关键修改2：member_points积分抵扣逻辑 ====================
    def _apply_points_discount(self, user_id: int, user, points_to_use: Decimal, amount: Decimal) -> None:
        # 关键修改：使用member_points字段进行积分校验
        user_points = Decimal(str(user.member_points))
        if user_points < points_to_use:
            raise OrderException(f"积分不足，当前{user_points:.4f}分")

        max_discount_points = amount * Decimal('0.5') / POINTS_DISCOUNT_RATE
        if points_to_use > max_discount_points:
            raise OrderException(f"积分抵扣不能超过订单金额的50%（最多{max_discount_points:.4f}分）")

        # 关键修改：扣减member_points，并更新company_points池
        self.session.execute(
            "UPDATE users SET member_points = member_points - %s WHERE id = %s",
            {"points": points_to_use, "user_id": user_id}
        )
        self.session.execute(
            "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = 'company_points'",
            {"points": points_to_use}
        )

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
    def _process_member_order(self, order_id: int, user_id: int, user,
                              unit_price: Decimal, quantity: int) -> None:
        total_amount = unit_price * quantity
        self._allocate_funds_to_pools(order_id, total_amount)

        old_level = user.member_level
        new_level = min(old_level + quantity, 6)

        self.session.execute(
            "UPDATE users SET member_level = %s, level_changed_at = NOW() WHERE id = %s",
            {"level": new_level, "user_id": user_id}
        )

        # 关键修改：发放member_points积分（DECIMAL类型）
        points_earned = unit_price * quantity
        new_points_dec = self._update_user_balance(user_id, 'member_points', points_earned)
        # 使用 helper 插入 points_log
        self._insert_points_log(user_id=user_id,
                                change_amount=points_earned,
                                balance_after=new_points_dec,
                                type='member',
                                reason='购买会员商品获得积分',
                                related_order=order_id)
        logger.debug(f"用户升级: {old_level}星 → {new_level}星, 获得积分: {points_earned:.4f}")

        self._create_pending_rewards(order_id, user_id, old_level, new_level)

        company_points = total_amount * Decimal('0.20')
        self._add_pool_balance('company_points', company_points, f"订单#{order_id} 公司积分分配")

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

    def _create_pending_rewards(self, order_id: int, buyer_id: int, old_level: int, new_level: int) -> None:
        if old_level == 0:
            result = self.session.execute(
                "SELECT referrer_id FROM user_referrals WHERE user_id = %s",
                {"user_id": buyer_id}
            )
            referrer = result.fetchone()
            if referrer and referrer.referrer_id:
                reward_amount = MEMBER_PRODUCT_PRICE * Decimal('0.50')
                self.session.execute(
                    """INSERT INTO pending_rewards (user_id, reward_type, amount, order_id, status)
                       VALUES (%s, 'referral', %s, %s, 'pending')""",
                    {
                        "user_id": referrer.referrer_id,
                        "amount": reward_amount,
                        "order_id": order_id
                    }
                )
                logger.debug(f"推荐奖励待审核: 用户{referrer.referrer_id} ¥{reward_amount}")

        if old_level == 0 and new_level == 1:
            logger.debug("0星升级1星，不产生团队奖励")
            return

        target_layer = new_level
        current_id = buyer_id
        target_referrer = None

        for _ in range(target_layer):
            result = self.session.execute(
                "SELECT referrer_id FROM user_referrals WHERE user_id = %s",
                {"user_id": current_id}
            )
            ref = result.fetchone()
            if not ref or not ref.referrer_id:
                break
            target_referrer = ref.referrer_id
            current_id = ref.referrer_id

        if target_referrer:
            # 使用动态表访问获取推荐人等级
            with get_conn() as conn:
                with conn.cursor() as cur:
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="id=%s",
                        select_fields=["member_level"]
                    )
                    cur.execute(select_sql, (target_referrer,))
                    row = cur.fetchone()
                    referrer_level = row.get('member_level', 0) or 0 if row else 0

            if referrer_level >= target_layer:
                reward_amount = MEMBER_PRODUCT_PRICE * Decimal('0.50')
                self.session.execute(
                    """INSERT INTO pending_rewards (user_id, reward_type, amount, order_id, layer, status)
                       VALUES (%s, 'team', %s, %s, %s, 'pending')""",
                    {
                        "user_id": target_referrer,
                        "amount": reward_amount,
                        "order_id": order_id,
                        "layer": target_layer
                    }
                )
                logger.debug(f"团队奖励待审核: 用户{target_referrer} L{target_layer} ¥{reward_amount}")

    def _process_normal_order(self, order_id: int, user_id: int, merchant_id: int,
                              final_amount: Decimal, member_level: int) -> None:
        if merchant_id != PLATFORM_MERCHANT_ID:
            merchant_amount = final_amount * Decimal('0.80')
            # 更新商家余额并记录流水
            # new_merchant_balance = self._update_user_balance(merchant_id, 'merchant_balance', merchant_amount)
            # self._insert_account_flow(account_type='merchant_balance',
            #                           related_user=merchant_id,
            #                           change_amount=merchant_amount,
            #                           flow_type='income',
            #                           remark=f"普通商品收益 - 订单#{order_id}")
            logger.debug(f"商家{merchant_id}到账: ¥{merchant_amount}")
        else:
            platform_amount = final_amount * Decimal('0.80')
            # 平台自营商品收入进入平台池子
            self._add_pool_balance('platform_revenue_pool', platform_amount, f"平台自营商品收入 - 订单#{order_id}")
            logger.debug(f"平台自营商品收入: ¥{platform_amount}")

            for purpose, percent in ALLOCATIONS.items():
                alloc_amount = final_amount * percent
                # 统一通过 helper 更新池子并记录流水
                self._add_pool_balance(purpose.value, alloc_amount, f"订单#{order_id} 分配到{purpose.value}",
                                       related_user=user_id)
                if purpose == AllocationKey.PUBLIC_WELFARE:
                    logger.debug(f"公益基金获得: ¥{alloc_amount}")

        # 关键修改：member_level>=1的用户发放member_points积分
        if member_level >= 1:
            points_earned = final_amount
            # 使用 helper 更新用户member_points并返回新积分
            new_points_dec = self._update_user_balance(user_id, 'member_points', points_earned)
            self._insert_points_log(user_id=user_id,
                                    change_amount=points_earned,
                                    balance_after=new_points_dec,
                                    type='member',
                                    reason='购买获得积分',
                                    related_order=order_id)
            logger.debug(f"用户获得积分: {points_earned:.4f}")

        # 关键修改：处理商家的merchant_points（DECIMAL精度）
        if merchant_id != PLATFORM_MERCHANT_ID:
            merchant_points = final_amount * Decimal('0.20')
            if merchant_points > Decimal('0'):
                new_mp_dec = self._update_user_balance(merchant_id, 'merchant_points', merchant_points)
                self._insert_points_log(user_id=merchant_id,
                                        change_amount=merchant_points,
                                        balance_after=new_mp_dec,
                                        type='merchant',
                                        reason='销售获得积分',
                                        related_order=order_id)
                logger.debug(f"商家获得积分: {merchant_points:.4f}")

    def audit_and_distribute_rewards(self, reward_ids: List[int], approve: bool, auditor: str = 'admin') -> bool:
        """批量审核奖励并发放优惠券"""
        try:
            if not reward_ids:
                raise FinanceException("奖励ID列表不能为空")

            placeholders, params = build_in_placeholders(reward_ids)

            result = self.session.execute(
                f"""SELECT id, user_id, reward_type, amount, order_id, layer
                   FROM pending_rewards WHERE id IN ({placeholders}) AND status = 'pending'""",
                params
            )
            rewards = result.fetchall()

            if not rewards:
                raise FinanceException("未找到待审核的奖励记录")

            if approve:
                today = datetime.now().date()
                valid_to = today + timedelta(days=COUPON_VALID_DAYS)

                for reward in rewards:
                    result = self.session.execute(
                        """INSERT INTO coupons (user_id, coupon_type, amount, valid_from, valid_to, status)
                           VALUES (%s, 'user', %s, %s, %s, 'unused')""",
                        {
                            "user_id": reward.user_id,
                            "amount": reward.amount,
                            "valid_from": today,
                            "valid_to": valid_to
                        }
                    )
                    coupon_id = result.lastrowid

                    self.session.execute(
                        "UPDATE pending_rewards SET status = 'approved' WHERE id = %s",
                        {"id": reward.id}
                    )

                    reward_desc = '推荐' if reward.reward_type == 'referral' else f"团队L{reward.layer}"
                    self._record_flow(
                        account_type='coupon',
                        related_user=reward.user_id,
                        change_amount=0,
                        flow_type='coupon',
                        remark=f"{reward_desc}奖励发放优惠券#{coupon_id} ¥{reward.amount:.2f}"
                    )
                    logger.debug(f"奖励{reward.id}已批准，发放优惠券{coupon_id}")
            else:
                self.session.execute(
                    f"UPDATE pending_rewards SET status = 'rejected' WHERE id IN ({placeholders})",
                    params
                )
                logger.debug(f"已拒绝 {len(reward_ids)} 条奖励")

            self.session.commit()
            return True

        except Exception as e:
            self.session.rollback()
            logger.error(f"❌ 审核奖励失败: {e}")
            return False

    def get_rewards_by_status(self, status: str = 'pending', reward_type: Optional[str] = None, limit: int = 50) -> \
            List[Dict[str, Any]]:
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 动态获取 pending_rewards 表的所有列
                cur.execute("SHOW COLUMNS FROM pending_rewards")
                columns = cur.fetchall()
                column_names = [col['Field'] for col in columns]

                # 资产字段列表（需要降级默认值的字段）
                asset_fields = ['amount']

                # 动态构造 SELECT 字段列表，对资产字段做降级默认值处理
                select_fields = []
                from core.table_access import _quote_identifier

                for col_name in column_names:
                    if col_name in asset_fields:
                        select_fields.append(f"COALESCE({_quote_identifier('pr.' + col_name)}, 0) AS {_quote_identifier(col_name)}")
                    else:
                        select_fields.append(_quote_identifier('pr.' + col_name))

                # 添加用户名称字段
                select_fields.append(f"{_quote_identifier('u.name')} AS {_quote_identifier('user_name')}")

                # 构造完整的 SELECT 语句
                params = [status, limit]
                sql = f"""SELECT {', '.join(select_fields)}
                         FROM pending_rewards pr JOIN users u ON pr.user_id = u.id WHERE pr.status = %s"""
                if reward_type:
                    sql += " AND pr.reward_type = %s"
                    params.insert(1, reward_type)
                sql += " ORDER BY pr.created_at DESC LIMIT %s"

                cur.execute(sql, tuple(params))
                rewards = cur.fetchall()

                # 动态构造返回结果
                result = []
                for r in rewards:
                    reward_dict = {}
                    for col_name in column_names:
                        value = r.get(col_name)
                        # 对资产字段转换为 float，其他字段保持原样
                        if col_name in asset_fields:
                            reward_dict[col_name] = float(value) if value is not None else 0.0
                        elif col_name == 'created_at' and value:
                            reward_dict[col_name] = value.strftime("%Y-%m-%d %H:%M:%S") if hasattr(value,
                                                                                                   'strftime') else str(
                                value)
                        else:
                            reward_dict[col_name] = value
                    # 添加用户名称
                    reward_dict['user_name'] = r.get('user_name')
                    result.append(reward_dict)

                return result

    # ==================== 关键修改5：周补贴使用member_points和merchant_points ====================
    def distribute_weekly_subsidy(self) -> bool:
        logger.info("周补贴发放开始（优惠券形式）")

        pool_balance = self.get_account_balance('subsidy_pool')
        if pool_balance <= 0:
            logger.warning("❌ 补贴池余额不足")
            return False

        # 使用动态表访问检查字段是否存在，然后使用 SUM 聚合
        # 关键修改：member_points替代points
        with get_conn() as conn:
            with conn.cursor() as cur:
                structure = get_table_structure(cur, "users", use_cache=False)
                # 检查 member_points 字段是否存在
                if "member_points" in structure['fields']:
                    cur.execute(
                        "SELECT SUM(COALESCE(member_points, 0)) as total FROM users WHERE COALESCE(member_points, 0) > 0")
                    row = cur.fetchone()
                    user_points = Decimal(str(row.get('total', 0) or 0))
                else:
                    user_points = Decimal('0')

                # 检查 merchant_points 字段是否存在
                if "merchant_points" in structure['fields']:
                    cur.execute(
                        "SELECT SUM(COALESCE(merchant_points, 0)) as total FROM users WHERE COALESCE(merchant_points, 0) > 0")
                    row = cur.fetchone()
                    merchant_points = Decimal(str(row.get('total', 0) or 0))
                else:
                    merchant_points = Decimal('0')

        result = self.session.execute(
            "SELECT balance as total FROM finance_accounts WHERE account_type = 'company_points'")
        company_points = Decimal(str(result.fetchone().total or 0))

        total_points = user_points + merchant_points + company_points

        if total_points <= 0:
            logger.warning("❌ 总积分为0，无法发放补贴")
            return False

        points_value = pool_balance / total_points
        if points_value > MAX_POINTS_VALUE:
            points_value = MAX_POINTS_VALUE

        logger.info(
            f"补贴池: ¥{pool_balance} | 用户积分: {user_points} | 商家积分: {merchant_points} | 公司积分: {company_points}（仅参与计算） | 积分值: ¥{points_value:.4f}/分")

        total_distributed = Decimal('0')
        today = datetime.now().date()
        valid_to = today + timedelta(days=COUPON_VALID_DAYS)

        # 使用动态表访问获取用户member_points积分信息
        with get_conn() as conn:
            with conn.cursor() as cur:
                structure = get_table_structure(cur, "users", use_cache=False)
                if "member_points" in structure['fields']:
                    select_sql = build_dynamic_select(
                        cur,
                        "users",
                        where_clause="COALESCE(member_points, 0) > 0",
                        select_fields=["id", "member_points"]
                    )
                    cur.execute(select_sql)
                    users_data = cur.fetchall()
                    # 转换为类似的对象列表以保持兼容性
                    users = [type('obj', (object,),
                                  {'id': row['id'], 'member_points': Decimal(str(row.get('member_points', 0) or 0))})()
                             for row in users_data]
                else:
                    users = []

        try:
            with self.session.begin():
                for user in users:
                    user_points = Decimal(str(user.member_points))
                    subsidy_amount = user_points * points_value
                    deduct_points = subsidy_amount / points_value if points_value > 0 else Decimal('0')

                    if subsidy_amount <= Decimal('0'):
                        continue

                    result = self.session.execute(
                        """INSERT INTO coupons (user_id, coupon_type, amount, valid_from, valid_to, status)
                           VALUES (%s, 'user', %s, %s, %s, 'unused')""",
                        {
                            "user_id": user.id,
                            "amount": subsidy_amount,
                            "valid_from": today,
                            "valid_to": valid_to
                        }
                    )
                    coupon_id = result.lastrowid

                    new_points = user_points - deduct_points
                    # 关键修改：扣减member_points
                    self.session.execute(
                        "UPDATE users SET member_points = %s WHERE id = %s",
                        {"points": new_points, "user_id": user.id}
                    )

                    self.session.execute(
                        """INSERT INTO weekly_subsidy_records (user_id, week_start, subsidy_amount, points_before, points_deducted, coupon_id)
                           VALUES (%s, %s, %s, %s, %s, %s)""",
                        {
                            "user_id": user.id,
                            "week_start": today,
                            "subsidy_amount": subsidy_amount,
                            "points_before": user_points,
                            "points_deducted": deduct_points,
                            "coupon_id": coupon_id
                        }
                    )

                    total_distributed += subsidy_amount
                    logger.info(f"用户{user.id}: 优惠券¥{subsidy_amount:.4f}, 扣积分{deduct_points:.4f}")

                # 处理商家的merchant_points
                result = self.session.execute("SELECT id, merchant_points FROM users WHERE merchant_points > 0")
                merchants = result.fetchall()

                for merchant in merchants:
                    merchant_points = Decimal(str(merchant.merchant_points))
                    subsidy_amount = merchant_points * points_value
                    deduct_points = subsidy_amount / points_value if points_value > 0 else Decimal('0')

                    if subsidy_amount <= Decimal('0'):
                        continue

                    result = self.session.execute(
                        """INSERT INTO coupons (user_id, coupon_type, amount, valid_from, valid_to, status)
                           VALUES (%s, 'merchant', %s, %s, %s, 'unused')""",
                        {
                            "user_id": merchant.id,
                            "amount": subsidy_amount,
                            "valid_from": today,
                            "valid_to": valid_to
                        }
                    )
                    coupon_id = result.lastrowid

                    new_points = merchant_points - deduct_points
                    # 关键修改：扣减merchant_points
                    self.session.execute(
                        "UPDATE users SET merchant_points = %s WHERE id = %s",
                        {"points": new_points, "user_id": merchant.id}
                    )

                    self.session.execute(
                        """INSERT INTO weekly_subsidy_records (user_id, week_start, subsidy_amount, points_before, points_deducted, coupon_id)
                           VALUES (%s, %s, %s, %s, %s, %s)""",
                        {
                            "user_id": merchant.id,
                            "week_start": today,
                            "subsidy_amount": subsidy_amount,
                            "points_before": merchant_points,
                            "points_deducted": deduct_points,
                            "coupon_id": coupon_id
                        }
                    )

                    total_distributed += subsidy_amount
                    logger.debug(f"商家{merchant.id}: 优惠券¥{subsidy_amount:.4f}, 扣积分{deduct_points:.4f}")

                logger.debug(f"公司积分{company_points}未扣除，未发放优惠券")

            logger.info(
                f"周补贴完成: 发放¥{total_distributed:.4f}优惠券（补贴池余额不变: ¥{pool_balance}，公司积分不扣除）")
            return True
        except Exception as e:
            logger.error(f"❌ 周补贴发放失败: {e}")
            return False

    # ==================== 关键修改4：退款逻辑使用member_points ====================
    def refund_order(self, order_no: str) -> bool:
        try:
            with self.session.begin():
                result = self.session.execute(
                    "SELECT * FROM orders WHERE order_number = %s FOR UPDATE",
                    {"order_number": order_no}
                )
                order = result.fetchone()

                if not order or order.status == 'refunded':
                    raise FinanceException("订单不存在或已退款")

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
        try:
            # 先获取表结构，动态构造 SELECT 语句（表结构查询不需要事务）
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("SHOW COLUMNS FROM withdrawals")
                    columns = cur.fetchall()

            # 识别资产字段关键词（数值类型字段）
            asset_keywords = ['balance', 'points', 'amount', 'total', 'frozen', 'available', 'tax']
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

            # 动态构造 SELECT 语句，使用 self.session 执行（确保在同一事务中）
            select_sql = f"SELECT {', '.join(select_fields)} FROM {_quote_identifier('withdrawals')} WHERE id = :withdrawal_id FOR UPDATE"
            result = self.session.execute(select_sql, {"withdrawal_id": withdrawal_id})
            withdraw = result.fetchone()

            if not withdraw or withdraw.status not in ['pending_auto', 'pending_manual']:
                raise FinanceException("提现记录不存在或已处理")

            new_status = 'approved' if approve else 'rejected'
            self.session.execute(
                """UPDATE withdrawals SET status = :status, audit_remark = :remark, processed_at = NOW()
                   WHERE id = :withdrawal_id""",
                {
                    "status": new_status,
                    "remark": f"{auditor}审核",
                    "withdrawal_id": withdrawal_id
                }
            )

            if approve:
                self._record_flow(
                    account_type='withdrawal',
                    related_user=withdraw.user_id,
                    change_amount=withdraw.actual_amount,
                    flow_type='income',
                    remark=f"提现到账 #{withdrawal_id}"
                )
                logger.debug(f"提现审核通过 #{withdrawal_id}，到账¥{withdraw.actual_amount:.2f}")
            else:
                balance_field = 'promotion_balance' if withdraw.withdrawal_type == 'user' else 'merchant_balance'
                self.session.execute(
                    f"UPDATE users SET {_quote_identifier(balance_field)} = {_quote_identifier(balance_field)} + :amount WHERE id = :user_id",
                    {"amount": withdraw.amount, "user_id": withdraw.user_id}
                )

                self._record_flow(
                    account_type=balance_field,
                    related_user=withdraw.user_id,
                    change_amount=withdraw.amount,
                    flow_type='income',
                    remark=f"提现拒绝退回 #{withdrawal_id}"
                )
                logger.debug(f"提现审核拒绝 #{withdrawal_id}")

            self.session.commit()
            return True

        except Exception as e:
            self.session.rollback()
            logger.error(f"❌ 提现审核失败: {e}")
            return False

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

    def _insert_account_flow(self, account_type: str, related_user: Optional[int],
                             change_amount: Decimal, flow_type: str,
                             remark: str, account_id: Optional[int] = None) -> None:
        """在 `account_flow` 中插入流水，并通过 `_get_balance_after` 计算插入时的余额。
        该函数应在事务上下文中调用（不负责提交/回滚）。"""
        balance_after = self._get_balance_after(account_type, related_user)
        self.session.execute(
            """INSERT INTO account_flow (account_id, account_type, related_user, change_amount, balance_after, flow_type, remark, created_at)
               VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())""",
            {
                "account_id": account_id,
                "account_type": account_type,
                "related_user": related_user,
                "change_amount": change_amount,
                "balance_after": balance_after,
                "flow_type": flow_type,
                "remark": remark
            }
        )

    def _add_pool_balance(self, account_type: str, amount: Decimal, remark: str,
                          related_user: Optional[int] = None) -> Decimal:
        """对平台/池子类账户 (`finance_accounts`) 增减余额并记录流水。
        返回更新后的余额（Decimal）。"""
        self.session.execute(
            "UPDATE finance_accounts SET balance = balance + %s WHERE account_type = %s",
            {"amount": amount, "type": account_type}
        )
        result = self.session.execute(
            "SELECT balance FROM finance_accounts WHERE account_type = %s",
            {"type": account_type}
        )
        row = result.fetchone()
        balance_after = Decimal(str(row.balance)) if row else Decimal('0')
        # 记录流水（income/expense 由 amount 正负决定）
        flow_type = 'income' if amount >= 0 else 'expense'
        self._insert_account_flow(account_type=account_type,
                                  related_user=related_user,
                                  change_amount=amount,
                                  flow_type=flow_type,
                                  remark=remark)
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
                        "remark": "周补贴改为发放优惠券"
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

        # ============= 1. 在事务外查询 =============
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

        # ============= 2. 使用 get_conn() 替代 self.session =============
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    total_distributed = Decimal('0')
                    for user in unilevel_users:
                        user_id = user['user_id']
                        weight = Decimal(str(user['level']))

                        dividend_amount = pool_balance * weight / total_weight
                        points_to_add = dividend_amount

                        # 使用位置参数 %s
                        cur.execute(
                            "UPDATE users SET points = COALESCE(points, 0) + %s WHERE id = %s",
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

    # services/finance_service.py

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

        # ============= 在事务外查询余额并过滤 =============
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

        # ============= 使用 get_conn() 替代 self.session =============
        cleared_pools = []
        total_cleared = Decimal('0')

        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    for pool_info in pools_to_clear:
                        pool_type = pool_info["account_type"]
                        account_name = pool_info["account_name"]
                        current_balance = pool_info["balance"]

                        # 执行清空操作（使用直接SQL执行）
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

                    conn.commit()

                logger.info(f"资金池清空完成: 共清空 {len(cleared_pools)} 个，总计 ¥{total_cleared:.2f}")

                return {
                    "cleared_pools": cleared_pools,
                    "total_cleared": float(total_cleared)
                }

        except Exception as e:
            logger.error(f"清空资金池失败: {e}", exc_info=True)
            raise


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
            "INSERT INTO finance_accounts (account_name, account_type, balance) VALUES (%s, %s, 0) ON DUPLICATE KEY UPDATE account_name=VALUES(account_name)",
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
