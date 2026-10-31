# core/scheduler.py
import asyncio
import fcntl  # 新增：用于文件锁
import sys
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from core.database import get_conn
from core.wx_pay_client import WeChatPayClient
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logging.getLogger("apscheduler").setLevel(logging.WARNING)
logging.getLogger("apscheduler.scheduler").setLevel(logging.WARNING)


class TaskScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.pay_client = WeChatPayClient()
        self.lock_file = None
        self._dist_lock = None
        self._payment_cursor = 0
        self._offline_payment_cursor = 0

    def _acquire_scheduler_lock(self) -> bool:
        if sys.platform != "win32":
            lock_file_path = "/tmp/scheduler.lock"
            try:
                self.lock_file = open(lock_file_path, "w")
                fcntl.flock(self.lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return True
            except BlockingIOError:
                return False
            except Exception as e:
                logger.error('scheduler_lock_failed')
                return False
        from core.distributed_lock import RedisRenewableLock

        self._dist_lock = RedisRenewableLock(
            "task:apscheduler", ttl_seconds=3600, renew_interval_seconds=600
        )
        return self._dist_lock.acquire()

    def start(self):
        """启动所有定时任务（带进程间锁：Linux fcntl / Windows Redis 续期锁）"""
        if not self._acquire_scheduler_lock():
            logger.info("另一个进程已持有调度器锁，本进程跳过启动定时任务")
            return

        self.scheduler.add_job(self.recover_payments, 'interval', minutes=1,
            id='payment_recovery', replace_existing=True, max_instances=1, coalesce=True)
        # 每天凌晨4点清理过期草稿
        self.scheduler.add_job(
            self.clean_expired_drafts,
            CronTrigger(hour=4, minute=0),
            id="clean_expired_drafts",
            replace_existing=True
        )

        # ===== 新增：每天凌晨2点同步微信订单状态 =====
        self.scheduler.add_job(
            self.sync_wechat_order_status,
            CronTrigger(hour=2, minute=0),
            id="sync_wechat_order_status",
            replace_existing=True
        )
        # ===========================================

        # 每10分钟轮询审核中的进件状态
        self.scheduler.add_job(
            self.poll_applyment_status,
            CronTrigger(minute="*/10"),
            id="poll_applyment_status",
            replace_existing=True
        )

        # 每天9点检查审核超时（超过2个工作日）
        self.scheduler.add_job(
            self.check_audit_timeout,
            CronTrigger(hour=9, minute=0),
            id="check_audit_timeout",
            replace_existing=True
        )

        # 每日 23:58 结算过期未用优惠券（面额入补贴池 + 等额会员积分），早于次日 0 点日补贴发放
        self.scheduler.add_job(
            self.settle_expired_coupons,
            CronTrigger(hour=23, minute=58),
            id="settle_expired_coupons",
            replace_existing=True,
            misfire_grace_time=3600,
            coalesce=True,
        )

        # 每天零点执行 V1.1 会员权益日结（积分→雨点→券、券过期入池）。
        # V1.1 采用日结，旧的"日补贴 @00:00"与"月度雨点转券 @每月1日"已停用（Q1/Q2 改为日结，废弃月结），
        # 旧方法保留但不再调度，避免同一积分被两套结算同时处理。
        self.scheduler.add_job(
            self.settle_v1_daily_rights,
            CronTrigger(hour=0, minute=0),
            id="v1_daily_rights_settlement",
            replace_existing=True,
            misfire_grace_time=3600,
            coalesce=True,
        )

        # 每月1日零点自动发放联创分红
        self.scheduler.add_job(
            self.auto_distribute_unilevel_dividend,
            CronTrigger(day=1, hour=0, minute=0),
            id="monthly_unilevel_auto",
            replace_existing=True,
            misfire_grace_time=3600
        )

        # 旧月度雨点转券（每月1日 00:05）已由 V1.1 日结替代，停止调度。
        # self.scheduler.add_job(
        #     self.settle_monthly_rain_points,
        #     CronTrigger(day=1, hour=0, minute=5),
        #     id="monthly_rain_point_coupon",
        #     replace_existing=True,
        #     misfire_grace_time=3600,
        #     coalesce=True,
        # )

        # 每小时清理过期银行卡验证码
        self.scheduler.add_job(
            self.clean_expired_bankcard_codes,
            CronTrigger(hour="*", minute=30),
            id="clean_expired_bankcard_codes",
            replace_existing=True
        )

        # Clean non-public avatar files after review requests expire.
        self.scheduler.add_job(
            self.clean_expired_avatar_reviews,
            CronTrigger(minute="*/10"),
            id="clean_expired_avatar_reviews",
            replace_existing=True,
            coalesce=True,
        )

        self.scheduler.start()
        logger.info("定时任务管理器已启动（当前进程持有锁）")

    def settle_expired_coupons(self):
        """过期未使用优惠券：面额归入补贴池，用户增加等额会员积分。"""
        try:
            from services.finance_service import FinanceService

            logger.info("[定时任务] 开始结算过期优惠券")
            result = FinanceService().settle_expired_unused_coupons()
            logger.info(
                "[定时任务] 过期优惠券结算完成: processed=%s total_amount=%s",
                result.get("processed"),
                result.get("total_amount"),
            )
        except Exception as e:
            logger.error('scheduled_coupon_expiry_failed')

    # ==================== V1.1 会员权益日结 ====================
    def settle_v1_daily_rights(self):
        """V1.1 每日结算：过期券入补贴池+1:1 回补积分 → 积分产雨点 → 雨点 1:1 转 30 天券。

        Q12（补贴池 12%/8% 下发）未确认，本任务不包含任何补贴池出池逻辑。
        """
        try:
            from services.settlement_service import SettlementService

            logger.info("[定时任务] 开始 V1.1 会员权益日结")
            summary = SettlementService().run_daily_settlement()
            logger.info("[定时任务] V1.1 会员权益日结完成: %s", summary)
        except Exception as e:
            logger.error("scheduled_v1_daily_settlement_failed: %s", e)

    # ==================== 日补贴发放（V1.1 已停用） ====================
    def auto_distribute_daily_subsidy(self):
        """每天零点自动发放日补贴"""
        try:
            from services.finance_service import FinanceService
            from core.exceptions import FinanceException

            logger.info("=" * 50)
            logger.info("[定时任务] 开始执行日补贴自动发放")
            logger.info(f"执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            service = FinanceService()
            success = service.distribute_daily_subsidy()

            if success:
                logger.info("[定时任务] 日补贴发放成功完成")
            else:
                logger.warning("[定时任务] 日补贴发放失败，可能余额不足或无可发放用户")

        except FinanceException as e:
            logger.warning('scheduled_subsidy_rejected')
        except Exception as e:
            logger.error('scheduled_subsidy_failed')

    # ==================== 联创分红发放 ====================
    def auto_distribute_unilevel_dividend(self):
        """每月1日零点自动发放联创分红"""
        try:
            from services.finance_service import FinanceService

            logger.info("=" * 50)
            logger.info("[定时任务] 开始执行联创分红自动发放")
            logger.info(f"执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            service = FinanceService()
            result = service.distribute_unilevel_dividend()

            if result:
                logger.info("[定时任务] 联创分红发放成功完成")
            else:
                logger.warning("[定时任务] 联创分红发放失败，可能余额不足或无符合条件的联创用户")

        except Exception as e:
            logger.error('scheduled_dividend_failed')

    def settle_monthly_rain_points(self):
        """Run the monthly rain-point to coupon conversion."""
        try:
            from services.finance_service import FinanceService
            result = FinanceService().settle_monthly_rain_points()
            logger.info("[scheduled] monthly rain-point conversion completed: %s", result)
        except Exception as e:
            logger.error('scheduled_rain_conversion_failed')

    def shutdown(self):
        """关闭定时任务，并释放锁"""
        if hasattr(self, 'scheduler') and self.scheduler.running:
            self.scheduler.shutdown()
        # ========== 新增：释放文件锁 ==========
        if self.lock_file:
            try:
                fcntl.flock(self.lock_file, fcntl.LOCK_UN)
                self.lock_file.close()
            except Exception as e:
                logger.warning('scheduler_unlock_failed')
        logger.info("定时任务管理器已关闭")

    # ==================== 原有方法完整保留 ====================
    def clean_expired_bankcard_codes(self):
        """清理过期银行卡验证码"""
        try:
            from services.bankcard_service import BankcardService
            deleted = BankcardService.clean_expired_codes()
            logger.info(f"[定时任务] 清理过期银行卡验证码: {deleted}条")
        except Exception as e:
            logger.error('scheduled_bankcode_cleanup_failed')

    def clean_expired_avatar_reviews(self):
        """Mark expired avatar reviews and remove their pending files."""
        try:
            from services.avatar_moderation_service import AvatarModerationService

            deleted = AvatarModerationService.expire_stale()
            if deleted:
                logger.info("[定时任务] 清理过期头像审核记录: %s", deleted)
        except Exception as e:
            logger.error('scheduled_avatar_cleanup_failed')

    def clean_expired_drafts(self):
        """清理过期草稿"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        DELETE FROM wx_applyment 
                        WHERE draft_expired_at < NOW() 
                        AND is_draft = 1
                    """)
                    deleted = cur.rowcount
                    conn.commit()
                    logger.info(f"清理了 {deleted} 条过期草稿")
        except Exception as e:
            logger.error('scheduled_draft_cleanup_failed')

    def poll_applyment_status(self):
        """轮询审核中的进件状态"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 获取所有审核中的进件
                    cur.execute("""
                        SELECT applyment_id, user_id 
                        FROM wx_applyment 
                        WHERE applyment_state = 'APPLYMENT_STATE_AUDITING'
                    """)
                    applyments = cur.fetchall()

                    for row in applyments:
                        try:
                            # 调用微信支付API查询状态
                            status_info = self.pay_client.query_applyment_status(row['applyment_id'])
                            new_state = status_info.get("applyment_state")

                            # 如果状态有变化，直接更新数据库并推送
                            if new_state and new_state != 'APPLYMENT_STATE_AUDITING':
                                # 更新状态
                                cur.execute("""
                                    UPDATE wx_applyment 
                                    SET applyment_state = %s, 
                                        applyment_state_msg = %s,
                                        sub_mchid = %s,
                                        finished_at = CASE WHEN %s = 'APPLYMENT_STATE_FINISHED' THEN NOW() ELSE finished_at END
                                    WHERE applyment_id = %s
                                """, (
                                    new_state,
                                    status_info.get("state_msg"),
                                    status_info.get("sub_mchid"),
                                    new_state,
                                    row['applyment_id']
                                ))

                                # 如果审核通过，绑定商户号并同步结算账户
                                if new_state == "APPLYMENT_STATE_FINISHED":
                                    sub_mchid = status_info.get("sub_mchid")

                                    # 1. 绑定商户号
                                    cur.execute("""
                                        UPDATE users u
                                        JOIN wx_applyment wa ON u.id = wa.user_id
                                        SET u.wechat_sub_mchid = %s
                                        WHERE wa.applyment_id = %s
                                    """, (sub_mchid, row['applyment_id']))

                                    # 2. 同步结算账户信息（复用service中的方法）
                                    from services.wechat_applyment_service import WechatApplymentService
                                    # 在循环外实例化服务类，避免重复创建
                                    service = WechatApplymentService()
                                    service._sync_settlement_account(cur, row['applyment_id'], row['user_id'],
                                                                     sub_mchid)

                                    # 关键修复：在推送前提交数据库事务
                                    conn.commit()

                                # 推送通知（使用同步方法）
                                from core.push_service import push_service
                                push_service.send_applyment_status_notification_sync(
                                    row['user_id'],
                                    new_state,
                                    status_info.get("state_msg", "")
                                )
                            else:
                                # 更新轮询时间
                                cur.execute("""
                                    UPDATE wx_applyment 
                                    SET applyment_state_msg = %s,
                                        updated_at = NOW()
                                    WHERE applyment_id = %s
                                """, (status_info.get("state_msg"), row['applyment_id']))
                                conn.commit()

                        except Exception as e:
                            logger.error('scheduled_applyment_query_failed')

        except Exception as e:
            logger.error('scheduled_applyment_poll_failed')

    def check_audit_timeout(self):
        """检查审核超时（超过2个工作日）"""
        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 计算2个工作日前的日期（简化处理）
                    timeout_date = datetime.now() - timedelta(days=3)  # 考虑周末

                    cur.execute("""
                        SELECT wa.id, wa.applyment_id, wa.user_id, u.name, u.mobile
                        FROM wx_applyment wa
                        JOIN users u ON wa.user_id = u.id
                        WHERE wa.applyment_state = 'APPLYMENT_STATE_AUDITING'
                        AND wa.submitted_at < %s
                        AND wa.is_timeout_alerted = 0
                    """, (timeout_date,))

                    timeout_applyments = cur.fetchall()
                    for applyment in timeout_applyments:
                        # 发送超时预警通知
                        logger.warning('applyment_audit_timeout id=%s', applyment['id'])

                        # 标记为已预警
                        cur.execute("""
                            UPDATE wx_applyment 
                            SET is_timeout_alerted = 1
                            WHERE id = %s
                        """, (applyment['id'],))

                    conn.commit()
                    logger.info(f"检查审核超时完成，发现 {len(timeout_applyments)} 条超时记录")

        except Exception as e:
            logger.error('scheduled_audit_timeout_failed')

    def recover_payments(self):
        from services.refund_service import RefundService
        from api.wechat_pay.routes import handle_transaction_success
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT out_refund_no FROM payment_refund_intents WHERE state IN ('prepared','unknown','processing') AND (next_attempt_at IS NULL OR next_attempt_at<=NOW()) ORDER BY id LIMIT 50")
                refunds = cur.fetchall()
                cur.execute("SELECT order_number FROM payment_merchant_transfers WHERE (state IN ('prepared','unknown','processing') OR (state='finished' AND notification_sent=0)) AND (next_attempt_at IS NULL OR next_attempt_at<=NOW()) ORDER BY order_number LIMIT 50")
                transfers = cur.fetchall()
                cur.execute("SELECT o.id,o.order_number FROM orders o LEFT JOIN payment_reconciliation_cases c ON c.order_number=o.order_number WHERE o.id>%s AND o.status IN ('pending_pay','cancelled') AND o.total_amount>0 AND c.case_key IS NULL ORDER BY o.id LIMIT 50", (self._payment_cursor,))
                orders = cur.fetchall()
                self._payment_cursor = orders[-1]['id'] if orders else 0
                cur.execute("SELECT id,order_no AS order_number FROM offline_order WHERE id>%s AND status=1 AND paid_amount>0 ORDER BY id LIMIT 50", (self._offline_payment_cursor,))
                offline = cur.fetchall()
                self._offline_payment_cursor = offline[-1]['id'] if offline else 0
                orders += offline
                cur.execute("INSERT IGNORE INTO payment_reconciliation_cases(case_key,order_number,transaction_id,total_fee,refund_no,reason) SELECT CONCAT('legacy:',o.refund_no),o.order_number,o.transaction_id,ROUND(o.total_amount*100),o.refund_no,'legacy_refund_missing_intent' FROM orders o LEFT JOIN payment_refund_intents i ON i.out_refund_no=o.refund_no WHERE o.refund_no IS NOT NULL AND o.refund_no<>'' AND i.id IS NULL AND o.status IN ('refunding','refunded')")
                conn.commit()
        for row in refunds:
            try:
                RefundService.recover(row['out_refund_no'])
            except Exception:
                logger.warning('refund_recovery_failed')
        for row in orders:
            try:
                result = self.pay_client.query_transaction(row['order_number'])
                if result.get('trade_state') == 'SUCCESS':
                    from core.config import settings
                    if result.get('mchid') != settings.WECHAT_PAY_MCH_ID or result.get('appid') != settings.WECHAT_APP_ID:
                        raise ValueError('Merchant mismatch')
                    asyncio.run(handle_transaction_success(result))
            except Exception:
                logger.warning('payment_recovery_failed')
        from services.payment_transfer_service import recover_transfer
        for row in transfers:
            try:
                recover_transfer(row['order_number'])
            except Exception:
                logger.warning('merchant_transfer_recovery_failed')

    def sync_wechat_order_status(self):
        """同步微信订单状态（每天凌晨2点执行）"""
        try:
            from services.wechat_shipping_v2_service import WechatShippingService
            from core.database import get_conn
            from api.order.order import OrderManager
            import time
            from datetime import datetime, timedelta

            wx_service = WechatShippingService()
            # 查询近 7 天已支付订单，与微信发货管理状态对齐（原仅昨天易漏单）
            range_start = int(
                time.mktime((datetime.now() - timedelta(days=7)).replace(hour=0, minute=0, second=0).timetuple())
            )
            range_end = int(time.time())

            last_index = ""
            while True:
                result = wx_service.get_order_list(
                    begin_time=range_start,
                    end_time=range_end,
                    last_index=last_index,
                    page_size=100
                )
                if result.get("errcode") != 0:
                    logger.error('shipping_status_query_failed')
                    break

                wx_orders = result.get("order_list", [])
                if not wx_orders:
                    break

                with get_conn() as conn:
                    with conn.cursor() as cur:
                        for wx_order in wx_orders:
                            transaction_id = wx_order.get("transaction_id")
                            wx_state = wx_order.get("order_state")  # 1待发货 2已发货 3确认收货 ...
                            merchant_trade_no = wx_order.get("merchant_trade_no")
                            if not transaction_id:
                                continue

                            cur.execute("SELECT id, order_number, status FROM orders WHERE transaction_id=%s FOR UPDATE",
                                        (transaction_id,))
                            local_order = cur.fetchone()
                            if not local_order:
                                continue

                            # 微信 order_state：1待发货 2已发货 3确认收货 4交易完成 …
                            st = local_order["status"]
                            if wx_state in (3, 4) and st == 'pending_recv':
                                logger.info(
                                    "微信订单已确认收货/交易完成，同步本地 completed: tx=%s local=%s",
                                    transaction_id,
                                    st,
                                )
                                OrderManager.update_status(
                                    local_order["order_number"], "completed", external_conn=conn
                                )
                            elif wx_state == 2 and st == "pending_ship":
                                logger.info(
                                    "微信侧已发货，本地仍为待发货，同步为待收货: tx=%s",
                                    transaction_id,
                                )
                                OrderManager.update_status(
                                    local_order["order_number"], "pending_recv", external_conn=conn
                                )
                    # ==================== 新增：提交事务 ====================
                    conn.commit()
                    # =======================================================

                if not result.get("has_more"):
                    break
                last_index = result.get("last_index", "")

            logger.info("微信订单状态同步任务完成")
        except Exception as e:
            logger.error('scheduled_order_sync_failed')

scheduler = TaskScheduler()
