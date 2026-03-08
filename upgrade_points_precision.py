#!/usr/bin/env python3
"""
积分字段精度升级脚本
将积分相关字段的小数位数从4位改为6位
"""

import pymysql
from core.config import get_db_config
from core.logging import get_logger

logger = get_logger(__name__)

def upgrade_points_precision():
    """升级积分字段精度"""
    try:
        config = get_db_config()
        conn = pymysql.connect(**config)
        cursor = conn.cursor()

        # 需要升级的字段
        upgrades = [
            ("users", "points", "DECIMAL(12,6) NOT NULL DEFAULT 0.000000"),
            ("users", "subsidy_points", "DECIMAL(12,6) NOT NULL DEFAULT 0.000000"),
            ("users", "team_reward_points", "DECIMAL(12,6) NOT NULL DEFAULT 0.000000"),
            ("users", "referral_points", "DECIMAL(12,6) NOT NULL DEFAULT 0.000000"),
            ("users", "true_total_points", "DECIMAL(12,6) NOT NULL DEFAULT 0.000000"),
            ("users", "member_points", "DECIMAL(12,6) NOT NULL DEFAULT 0.000000"),
            ("users", "merchant_points", "DECIMAL(12,6) NOT NULL DEFAULT 0.000000"),
            ("orders", "points_discount", "DECIMAL(12,6) NOT NULL DEFAULT 0.000000"),
            ("products", "max_points_discount", "DECIMAL(12,6) DEFAULT NULL"),
            ("points_log", "change_amount", "DECIMAL(12,6) NOT NULL"),
            ("points_log", "balance_after", "DECIMAL(12,6) NOT NULL"),
            ("pending_rewards", "amount", "DECIMAL(12,6) NOT NULL"),
        ]

        for table, column, new_type in upgrades:
            try:
                sql = f"ALTER TABLE {table} MODIFY COLUMN {column} {new_type}"
                cursor.execute(sql)
                logger.info(f"升级字段 {table}.{column} 成功")
            except Exception as e:
                logger.error(f"升级字段 {table}.{column} 失败: {e}")

        conn.commit()
        logger.info("积分字段精度升级完成")

    except Exception as e:
        logger.error(f"升级失败: {e}")
        raise
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    upgrade_points_precision()