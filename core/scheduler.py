# core/scheduler.py
import asyncio
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from core.database import get_conn
from core.wx_pay_client import WeChatPayClient  # ✅ 修复：WechatPayClient → WeChatPayClient
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class TaskScheduler:
    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self.pay_client = WeChatPayClient()  # ✅ 修复：WechatPayClient → WeChatPayClient

    def start(self):
        """启动所有定时任务"""
        # 延迟导入，避免启动时循环依赖
        from api.order.wechat_shipping import WechatShippingManager

        # 每天凌晨2点清理过期草稿
        self.scheduler.add_job(
            self.clean_expired_drafts,
            CronTrigger(hour=2, minute=0),
            id="clean_expired_drafts",
            replace_existing=True
        )

        # 每5分钟轮询审核中的进件状态
        self.scheduler.add_job(
            self.poll_applyment_status,
            CronTrigger(minute="*/5"),
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

        # ==================== 新增：每周六零点自动发放周补贴 ====================
        self.scheduler.add_job(
            self.auto_distribute_weekly_subsidy,
            CronTrigger(day_of_week=5, hour=0, minute=0),  # 每周六 00:00:00 (0=周一, 5=周六, 6=周日)
            id="weekly_subsidy_auto",
            replace_existing=True,
            misfire_grace_time=3600  # 容错1小时
        )

        # ==================== 新增：每月1日零点自动发放联创分红 ====================
        self.scheduler.add_job(
            self.auto_distribute_unilevel_dividend,
            CronTrigger(day=1, hour=0, minute=0),  # 每月1号 00:00:00
            id="monthly_unilevel_auto",
            replace_existing=True,
            misfire_grace_time=3600
        )

        # 每天12:00 刷新微信快递公司列表缓存
        self.scheduler.add_job(
            WechatShippingManager.refresh_delivery_list_cache,
            CronTrigger(hour=12, minute=0),
            id="refresh_delivery_list_daily",
            replace_existing=True,
            misfire_grace_time=3600
        )

        self.scheduler.start()
        logger.info("定时任务管理器已启动")

    # ==================== 新增方法：执行周补贴发放 ====================
    def auto_distribute_weekly_subsidy(self):
        """每周六零点自动发放周补贴"""
        try:
            from services.finance_service import FinanceService

            logger.info("=" * 50)
            logger.info("[定时任务] 开始执行周补贴自动发放")
            logger.info(f"执行时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            service = FinanceService()
            success = service.distribute_weekly_subsidy()

            if success:
                logger.info("[定时任务] 周补贴发放成功完成")
            else:
                logger.warning("[定时任务] 周补贴发放失败，可能余额不足或无可发放用户")

        except Exception as e:
            logger.error(f"[定时任务] 周补贴发放异常: {str(e)}", exc_info=True)

    # ==================== 新增方法：执行联创分红发放 ====================
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
            logger.error(f"[定时任务] 联创分红发放异常: {str(e)}", exc_info=True)

    def shutdown(self):
        """关闭定时任务"""
        self.scheduler.shutdown()
        logger.info("定时任务管理器已关闭")

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
            logger.error(f"清理过期草稿失败: {str(e)}", exc_info=True)

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
                            logger.error(f"轮询进件 {row['applyment_id']} 状态失败: {str(e)}")

        except Exception as e:
            logger.error(f"轮询进件状态失败: {str(e)}", exc_info=True)

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
                        logger.warning(
                            f"进件审核超时预警: 用户 {applyment['name']} ({applyment['mobile']}) "
                            f"进件 {applyment['applyment_id']} 已超时2个工作日未处理"
                        )

                        # 标记为已预警
                        cur.execute("""
                            UPDATE wx_applyment 
                            SET is_timeout_alerted = 1
                            WHERE id = %s
                        """, (applyment['id'],))

                    conn.commit()
                    logger.info(f"检查审核超时完成，发现 {len(timeout_applyments)} 条超时记录")

        except Exception as e:
            logger.error(f"检查审核超时失败: {str(e)}", exc_info=True)


scheduler = TaskScheduler()