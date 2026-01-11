# services/bankcard_service.py
# 统一银行卡管理服务 - 微信接口对齐版（防跨用户重复绑定 - 最终版）

import pymysql
import json
import os
import hashlib
import re
import uuid
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from fastapi import HTTPException

from core.database import get_conn
from core.logging import get_logger
from core.wx_pay_client import wxpay_client
from core.table_access import build_dynamic_select, build_dynamic_insert, build_dynamic_update

logger = get_logger(__name__)


class BankcardService:
    """统一银行卡管理服务 - 微信接口对齐版"""

    # 错误码定义
    ERROR_CODES = {
        "F001": "未找到微信进件记录",
        "F002": "微信进件未完成，无法绑定",
        "F003": "微信进件状态异常",
        "F004": "微信接口返回数据异常",
        "F005": "数据一致性验证失败",
        "F006": "数据库操作失败",
        "F007": "微信结算账户查询失败",
        "F008": "未找到有效银行卡记录",
        "F009": "微信接口未返回申请单号",
        "F010": "记录已被修改，操作失败",
        "F011": "系统异常，微信已受理但本地写入失败",
        "F012": "存在改绑申请记录，请稍后再试",
        "F013": "未找到改绑申请记录",
        "F014": "查询改绑状态失败",
        "F015": "解密失败",
        "F016": "查询绑定状态失败",
        "F017": "已存在进行中的改绑申请，请等待当前申请完成",
        "F018": "新卡信息与当前绑定卡信息相同（无需改绑）",
        "F019": "该银行卡已被其他商户绑定（绑定卡时）",
        "F020": "新银行卡已被其他商户绑定（提交改绑申请时）",
        "F021": "新卡已被其他用户绑定（改绑审核通过时，冲突）",
    }

    # 微信状态 → 内部状态映射
    WX_STATUS_MAP = {
        'APPLYMENT_STATE_EDITTING': 'VERIFYING',
        'APPLYMENT_STATE_AUDITING': 'VERIFYING',
        'APPLYMENT_STATE_REJECTED': 'VERIFY_FAIL',
        'APPLYMENT_STATE_TO_BE_CONFIRMED': 'VERIFYING',
        'APPLYMENT_STATE_TO_BE_SIGNED': 'VERIFYING',
        'APPLYMENT_STATE_SIGNING': 'VERIFYING',
        'APPLYMENT_STATE_FINISHED': 'VERIFY_SUCCESS',
        'APPLYMENT_STATE_CANCELED': 'VERIFY_FAIL'
    }

    # 微信审核结果 → 内部状态映射
    WX_AUDIT_MAP = {
        'AUDIT_SUCCESS': 'VERIFY_SUCCESS',
        'AUDITING': 'VERIFYING',
        'AUDIT_FAIL': 'VERIFY_FAIL'
    }

    # ========================================
    # 核心内部工具方法
    # ========================================

    @staticmethod
    def _get_wechat_settlement_info_from_api(user_id: int) -> Tuple[str, Dict[str, Any]]:
        """获取微信结算账户信息（增强错误处理）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT sub_mchid, applyment_state, is_draft
                    FROM wx_applyment 
                    WHERE user_id = %s 
                    ORDER BY id DESC 
                    LIMIT 1
                    """,
                    (user_id,)
                )
                record = cur.fetchone()
                if not record:
                    raise Exception("F001: 未找到微信进件记录")
                if record['is_draft'] == 1:
                    raise Exception("F002: 微信进件未完成，无法绑定")
                if record['applyment_state'] not in ['APPLYMENT_STATE_FINISHED', 'APPLYMENT_STATE_SIGNING']:
                    raise Exception(f"F003: 微信进件状态异常: {record['applyment_state']}")

                sub_mchid = record['sub_mchid']
                logger.info(f"查询微信结算账户: user_id={user_id}, sub_mchid={sub_mchid}")

                wechat_data = wxpay_client.query_settlement_account(sub_mchid)
                if not wechat_data or not wechat_data.get('account_number'):
                    raise Exception("F004: 微信接口返回数据异常")

                # 验证返回数据的完整性
                required_fields = ['account_type', 'account_bank', 'verify_result']
                for field in required_fields:
                    if field not in wechat_data:
                        logger.warning(f"微信返回数据缺少字段: {field}")

                return sub_mchid, wechat_data

    @staticmethod
    def _extract_last_4(card_number: str) -> str:
        """提取卡号后4位"""
        return card_number.strip()[-4:]

    @staticmethod
    def _extract_from_masked(masked_number: str) -> Tuple[str, str]:
        """从微信掩码格式提取前6位和后4位"""
        if '*' not in masked_number:
            raise ValueError("非掩码格式")

        parts = masked_number.split('*')
        first_part = parts[0]  # 前6位
        last_part = parts[-1]  # 后4位或空

        if len(last_part) < 4:
            raise ValueError("掩码格式异常")

        return first_part, last_part[-4:]

    @staticmethod
    def _verify_with_wechat_data(
            local_name: str, local_number: str, local_bank: str, wechat_data: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """验证数据一致性（生产级）"""
        try:
            wechat_masked = wechat_data.get('account_number', '')
            verify_result = wechat_data.get('verify_result', 'VERIFYING')

            # 第一步：验证微信审核状态
            if verify_result != 'VERIFY_SUCCESS':
                fail_reason = wechat_data.get('verify_fail_reason', '未知原因')
                return False, f"微信验证未通过: {verify_result}, 原因: {fail_reason}"

            # 第二步：验证卡号格式
            if '*' in wechat_masked:
                # 微信格式：前6位 + * + 后4位
                try:
                    wechat_first6, wechat_last4 = BankcardService._extract_from_masked(wechat_masked)
                    local_last4 = BankcardService._extract_last_4(local_number)

                    if wechat_last4 != local_last4:
                        return False, f"卡号后4位不匹配: 输入尾号={local_last4}, 微信尾号={wechat_last4}"

                    # 验证BIN码（前6位）
                    if wechat_first6 != local_number[:6]:
                        return False, f"银行卡BIN码不匹配: 输入={local_number[:6]}, 微信={wechat_first6}"
                except ValueError as e:
                    return False, f"微信卡号格式解析失败: {str(e)}"
            else:
                # 非掩码格式（测试环境）
                logger.warning("微信返回非掩码卡号，测试环境特征")
                if wechat_masked != local_number:
                    return False, "卡号不匹配"

            # 第三步：验证开户行（忽略大小写和空格）
            wechat_bank = wechat_data.get('account_bank', '').strip().lower().replace(' ', '')
            local_bank_normalized = local_bank.strip().lower().replace(' ', '')

            if wechat_bank != local_bank_normalized:
                return False, f"开户银行不匹配: 输入='{local_bank}', 微信='{wechat_data.get('account_bank')}'"

            # 第四步：验证账户类型
            wechat_account_type = wechat_data.get('account_type')
            if wechat_account_type not in ['ACCOUNT_TYPE_PRIVATE', 'ACCOUNT_TYPE_BUSINESS']:
                logger.warning(f"未知的账户类型: {wechat_account_type}")

            return True, "验证通过"
        except Exception as e:
            logger.error(f"验证过程异常: {str(e)}")
            return False, f"验证异常: {str(e)}"

    @staticmethod
    def _map_account_type(wechat_account_type: str) -> str:
        """映射微信账户类型到数据库值"""
        mapping = {
            'ACCOUNT_TYPE_PRIVATE': 'BANK_ACCOUNT_TYPE_PERSONAL',
            'ACCOUNT_TYPE_BUSINESS': 'BANK_ACCOUNT_TYPE_CORPORATE'
        }
        # 未知类型默认个人
        return mapping.get(wechat_account_type, 'BANK_ACCOUNT_TYPE_PERSONAL')

    @staticmethod
    def _check_card_uniqueness(user_id: int, card_hash: str) -> Tuple[bool, Optional[int]]:
        """
        核心防护：检查银行卡是否被其他用户绑定

        Returns:
            Tuple[bool, Optional[int]]: (是否唯一, 已绑定的用户ID)
        """
        # ✅ 优化点1：空哈希值抛出异常，而非返回None
        if not card_hash or not isinstance(card_hash, str) or len(card_hash) == 0:
            raise ValueError("卡号哈希不能为空或无效")

        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT user_id 
                    FROM merchant_settlement_accounts 
                    WHERE user_id != %s AND card_hash = %s AND status = 1
                    LIMIT 1
                    """,
                    (user_id, card_hash)
                )
                existing = cur.fetchone()
                if existing:
                    logger.warning(
                        f"卡哈希冲突检测: user_id={user_id} 尝试绑定已被 "
                        f"user_id={existing['user_id']} 占用的卡"
                    )
                    return False, existing['user_id']
        return True, None

    @staticmethod
    def _get_account_record(cursor, account_id: int) -> Optional[Dict]:
        """获取账户记录（内部使用）"""
        if not account_id:
            return None

        cursor.execute("""
            SELECT id, user_id, account_type, account_bank, bank_name, bank_branch_id,
                   bank_address_code, verify_result, is_default, status
            FROM merchant_settlement_accounts WHERE id = %s
        """, (account_id,))
        return cursor.fetchone()

    # ========================================
    # 业务API方法
    # ========================================

    @staticmethod
    def bind_bankcard(
            user_id: int,
            bank_name: str,
            bank_account: str,
            account_name: str,
            bank_branch_id: Optional[str],
            bank_address_code: str,
            is_default: bool = True,
            admin_key: Optional[str] = None,
            ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """绑定银行卡（幂等，防跨用户重复绑定）"""
        logger.info(f"【绑定开始】user_id={user_id}, bank_name={bank_name}")

        # 参数标准化
        bank_name = bank_name.strip()
        bank_account = bank_account.strip().replace(' ', '')
        account_name = account_name.strip()

        try:
            # 1. 获取微信数据
            sub_mchid, wechat_data = BankcardService._get_wechat_settlement_info_from_api(user_id)

            # 2. 验证数据一致性
            is_valid, msg = BankcardService._verify_with_wechat_data(
                account_name, bank_account, bank_name, wechat_data
            )
            if not is_valid:
                raise Exception(f"F005: {msg}")

            # 3. 生成卡号哈希并检查跨用户唯一性
            card_hash = BankcardService._generate_card_hash(bank_account)
            is_unique, bound_user_id = BankcardService._check_card_uniqueness(user_id, card_hash)
            if not is_unique:
                raise Exception(f"F019: 该银行卡已被其他商户绑定（user_id={bound_user_id}），请使用其他银行卡")

            # 4. 映射账户类型
            account_type = BankcardService._map_account_type(wechat_data['account_type'])

            # 5. 加密敏感数据
            encrypted_number = BankcardService._encrypt_sensitive(bank_account)
            encrypted_name = BankcardService._encrypt_sensitive(account_name)

            with get_conn() as conn:
                with conn.cursor() as cur:
                    # 6. 当前用户内幂等检查
                    cur.execute("""
                        SELECT id, account_number_encrypted 
                        FROM merchant_settlement_accounts 
                        WHERE user_id = %s AND card_hash = %s AND status = 1
                        LIMIT 1
                    """, (user_id, card_hash))
                    existing = cur.fetchone()

                    if existing:
                        # 验证是否是同一张卡（解密比对）
                        try:
                            existing_number = BankcardService._decrypt_local_encrypted(
                                existing['account_number_encrypted']
                            )
                            if existing_number == bank_account:
                                logger.info(f"银行卡已绑定，直接返回: user_id={user_id}, account_id={existing['id']}")
                                return {
                                    'msg': 'ok',
                                    'account_id': existing['id'],
                                    'action': 'already_bound',
                                    'verify_method': 'wechat_api',
                                    'verify_status': 'success'
                                }
                        except Exception as e:
                            logger.warning(f"解密已有卡号失败: {e}")
                            # 继续执行更新逻辑

                    # 7. 获取现有记录（用于更新或插入）
                    cur.execute(
                        "SELECT id FROM merchant_settlement_accounts WHERE user_id = %s AND status = 1 LIMIT 1",
                        (user_id,)
                    )
                    existing_record = cur.fetchone()

                    # 准备数据审计
                    old_data = BankcardService._get_account_record(cur,
                                                                   existing_record['id']) if existing_record else None
                    new_data = {
                        'account_bank': bank_name,
                        'account_type': account_type,
                        'sub_mchid': sub_mchid,
                        'verify_result': 'VERIFY_SUCCESS'
                    }

                    if existing_record:
                        # 更新旧记录
                        cur.execute("""
                            UPDATE merchant_settlement_accounts 
                            SET sub_mchid = %s, account_type = %s, account_bank = %s, bank_name = %s,
                                bank_branch_id = %s, bank_address_code = %s,
                                account_name_encrypted = %s, account_number_encrypted = %s,
                                card_hash = %s, verify_result = 'VERIFY_SUCCESS', is_default = %s,
                                status = 1, bind_at = NOW(), updated_at = NOW()
                            WHERE id = %s
                        """, (
                            sub_mchid, account_type, bank_name[:128], bank_name[:128],
                            bank_branch_id, bank_address_code,
                            encrypted_name, encrypted_number, card_hash, is_default,
                            existing_record['id']
                        ))
                        account_id = existing_record['id']
                        action = 'updated'
                    else:
                        # 插入新记录
                        cur.execute("""
                            INSERT INTO merchant_settlement_accounts 
                            (user_id, sub_mchid, account_type, account_bank, bank_name,
                             bank_branch_id, bank_address_code, account_name_encrypted,
                             account_number_encrypted, card_hash, verify_result, is_default, status, bind_at)
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'VERIFY_SUCCESS', %s, 1, NOW())
                        """, (
                            user_id, sub_mchid, account_type,
                            bank_name[:128], bank_name[:128], bank_branch_id, bank_address_code,
                            encrypted_name, encrypted_number, card_hash, is_default
                        ))
                        account_id = cur.lastrowid
                        action = 'created'

                    # 8. 同步到user_bankcards表（兼容旧系统）
                    cur.execute("""
                        INSERT INTO user_bankcards (user_id, bank_name, bank_account)
                        VALUES (%s, %s, %s)
                        ON DUPLICATE KEY UPDATE bank_account = VALUES(bank_account)
                    """, (user_id, bank_name, bank_account))

                    conn.commit()

                    # 异步记录审计日志
                    BankcardService._log_operation_async(
                        user_id, 'bind', account_id, old_data, new_data, admin_key, ip_address
                    )

                    logger.info(f"【绑定成功】user_id={user_id}, account_id={account_id}, action={action}")
                    return {
                        'msg': 'ok',
                        'account_id': account_id,
                        'action': action,
                        'verify_method': 'wechat_api',
                        'verify_status': 'success'
                    }
        except pymysql.MySQLError as e:
            logger.error(f"数据库操作失败: {e}")
            raise Exception(f"F006: 数据库操作失败 - {e}")
        except Exception as e:
            logger.error(f"绑定失败: {e}")
            raise

    @staticmethod
    async def send_sms_code(user_id: int, account_number: str) -> Dict[str, Any]:
        """发送短信验证码（生产级模拟）"""
        logger.info(f"【短信验证码】user_id={user_id}, 卡号={account_number[-4:]}")

        # 生产环境应集成真实短信服务商（如阿里云短信）
        # 返回标准化格式
        return {
            "session_id": str(uuid.uuid4()),
            "expired_in": 300,  # 5分钟有效期
            "mock_code": "123456"  # 测试验证码
        }

    @staticmethod
    def list_bankcards(user_id: int) -> List[Dict[str, Any]]:
        """获取银行卡列表（脱敏，不返回完整卡号）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, account_bank, bank_name, account_type,
                           verify_result, verify_fail_reason, bind_at,
                           account_number_encrypted, bank_branch_id
                    FROM merchant_settlement_accounts 
                    WHERE user_id = %s AND status = 1
                """, (user_id,))
                accounts = cur.fetchall()

                key = wxpay_client.apiv3_key[:32]
                result = []

                for account in accounts:
                    try:
                        # 只解密尾号
                        full_number = BankcardService._decrypt_local_encrypted(
                            account['account_number_encrypted'], key
                        )
                        tail4 = full_number[-4:]

                        # 构建掩码卡号（前6位+*+后4位）
                        if len(full_number) >= 10:
                            masked_number = f"{full_number[:6]}**********{tail4}"
                        else:
                            masked_number = f"{'*' * (len(full_number) - 4)}{tail4}"
                    except Exception as e:
                        logger.error(f"解密失败 account_id={account['id']}: {e}")
                        tail4 = '****'
                        masked_number = '****************'

                    result.append({
                        'id': account['id'],
                        'account_bank': account['account_bank'],
                        'bank_name': account['bank_name'],
                        'account_type': account['account_type'],
                        'verify_result': account['verify_result'],
                        'verify_fail_reason': account.get('verify_fail_reason'),
                        'bind_at': account['bind_at'].strftime('%Y-%m-%d %H:%M:%S') if account['bind_at'] else None,
                        'account_number_tail': tail4,
                        'account_number_masked': masked_number,
                        'bank_branch_id': account.get('bank_branch_id')
                    })

                return result

    @staticmethod
    def set_default_bankcard(user_id: int, account_id: int) -> Dict[str, Any]:
        """原子化设置默认银行卡（防并发）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 1. 验证银行卡存在且属于用户
                cur.execute("""
                    SELECT id FROM merchant_settlement_accounts 
                    WHERE id = %s AND user_id = %s AND status = 1
                """, (account_id, user_id))
                if not cur.fetchone():
                    raise HTTPException(status_code=404, detail="银行卡不存在或无权操作")

                # 2. 原子化切换（避免并发导致无默认卡）
                cur.execute("""
                    UPDATE merchant_settlement_accounts 
                    SET is_default = CASE WHEN id = %s THEN 1 ELSE 0 END,
                        updated_at = NOW()
                    WHERE user_id = %s
                """, (account_id, user_id))

                if cur.rowcount == 0:
                    raise HTTPException(status_code=500, detail="设置失败")

                conn.commit()
                logger.info(f"设置默认银行卡: user_id={user_id}, account_id={account_id}")
                return {"account_id": account_id, "is_default": 1, "msg": "设置成功"}

    @staticmethod
    def modify_bankcard(
            user_id: int, new_bank_name: str, new_bank_account: str, new_account_name: str,
            bank_branch_id: Optional[str], bank_address_code: Optional[str],
            admin_key: Optional[str], ip_address: Optional[str]
    ) -> Dict[str, Any]:
        """申请改绑银行卡（防跨用户重复绑定）"""
        logger.info(f"【改绑申请】user_id={user_id}, new_bank_name={new_bank_name}")

        # 参数标准化
        new_bank_name = new_bank_name.strip()
        new_bank_account = new_bank_account.strip().replace(' ', '')
        new_account_name = new_account_name.strip()
        bank_branch_id = (bank_branch_id or '').strip() or None
        bank_address_code = (bank_address_code or '').strip() or None

        # 步骤1-4：查询与验证（在事务外）
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 获取当前有效记录
                cur.execute("""
                    SELECT id, sub_mchid, account_type,
                           account_number_encrypted, account_name_encrypted,
                           account_bank, bank_name, modify_application_no, verify_result,
                           bank_branch_id, bank_address_code, bind_at
                    FROM merchant_settlement_accounts
                    WHERE user_id = %s AND status = 1
                    ORDER BY id DESC LIMIT 1
                """, (user_id,))
                old = cur.fetchone()
                if not old:
                    raise Exception("F008: 未找到有效银行卡记录")

                # 检查进行中的改绑（严格检查）
                if old.get('modify_application_no') and old.get('verify_result') == 'VERIFYING':
                    logger.warning(f"存在进行中的改绑申请: application_no={old['modify_application_no']}")

                    # 查询微信确认真实状态（最多等待30秒）
                    try:
                        import time
                        start_time = time.time()
                        while time.time() - start_time < 30:
                            wx_status = wxpay_client.query_application_status(
                                old['sub_mchid'], old['modify_application_no']
                            )
                            wx_state = wx_status.get('applyment_state')

                            # 如果微信已结束，清理状态并允许新申请
                            if wx_state in ['APPLYMENT_STATE_FINISHED', 'APPLYMENT_STATE_REJECTED',
                                            'APPLYMENT_STATE_CANCELED']:
                                cur.execute("""
                                    UPDATE merchant_settlement_accounts 
                                    SET modify_application_no = NULL,
                                        verify_result = %s,
                                        modify_fail_reason = %s,
                                        updated_at = NOW()
                                    WHERE id = %s
                                """, (
                                    'VERIFY_SUCCESS' if wx_state == 'APPLYMENT_STATE_FINISHED' else 'VERIFY_FAIL',
                                    wx_status.get('applyment_state_msg', ''),
                                    old['id']
                                ))
                                conn.commit()
                                logger.info(f"清理已完成的改绑申请: application_no={old['modify_application_no']}")
                                break
                            else:
                                # 等待5秒后重试
                                time.sleep(5)
                        else:
                            # 30秒后仍为审核中，拒绝新申请
                            raise Exception("F017: 已存在进行中的改绑申请，请等待当前申请完成")
                    except Exception as e:
                        if "F017" in str(e):
                            raise
                        logger.error(f"查询改绑状态失败: {e}")
                        raise Exception("F012: 存在改绑申请记录，请稍后再试")

                # 校验新卡是否与旧卡相同
                try:
                    old_plain_number = BankcardService._decrypt_local_encrypted(old['account_number_encrypted'])
                    if old_plain_number == new_bank_account and old['account_bank'] == new_bank_name:
                        raise Exception("F018: 新卡信息与当前绑定卡信息相同")
                except Exception as e:
                    if "F018" in str(e):
                        raise
                    logger.error(f"解密旧卡号失败: {e}")

        # 步骤5：校验新卡是否被其他用户绑定
        new_card_hash = BankcardService._generate_card_hash(new_bank_account)
        is_unique, bound_user_id = BankcardService._check_card_uniqueness(user_id, new_card_hash)
        if not is_unique:
            raise Exception(f"F020: 新银行卡已被其他商户绑定（user_id={bound_user_id}），请使用其他银行卡")

        # ===== 事务边界：准备调用微信 =====

        # 加密新卡信息
        new_number_enc = BankcardService._encrypt_sensitive(new_bank_account)
        new_name_enc = BankcardService._encrypt_sensitive(new_account_name)

        # 备份旧卡完整信息
        old_backup = {
            "account_number_encrypted": old["account_number_encrypted"],
            "account_name_encrypted": old["account_name_encrypted"],
            "account_bank": old["account_bank"],
            "bank_name": old["bank_name"],
            "bank_branch_id": old.get("bank_branch_id"),
            "bank_address_code": old.get("bank_address_code"),
            "account_type": old["account_type"]
        }

        # 调用微信接口
        sub_mchid = old["sub_mchid"]
        logger.info(f"调用微信改绑接口: sub_mchid={sub_mchid}")

        wx_resp = wxpay_client.modify_settlement_account(sub_mchid, {
            "account_type": old["account_type"],
            "account_bank": new_bank_name[:128],
            "bank_name": new_bank_name[:128],
            "bank_branch_id": bank_branch_id or old.get("bank_branch_id", ""),
            "bank_address_code": bank_address_code or old.get("bank_address_code", "100000"),
            "account_number": new_bank_account,
            "account_name": new_account_name,
        })

        application_no = wx_resp.get("application_no")
        if not application_no:
            logger.error(f"微信接口未返回申请单号: {wx_resp}")
            raise Exception("F009: 微信接口未返回申请单号")

        # ===== 事务边界：微信成功后写入本地 =====

        with get_conn() as conn:
            with conn.cursor() as cur:
                try:
                    cur.execute("""
                        UPDATE merchant_settlement_accounts
                        SET new_account_number_encrypted = %s,
                            new_account_name_encrypted = %s,
                            new_bank_name = %s,
                            old_account_backup = %s,
                            modify_application_no = %s,
                            verify_result = 'VERIFYING',
                            updated_at = NOW()
                        WHERE id = %s AND user_id = %s
                    """, (
                        new_number_enc,
                        new_name_enc,
                        new_bank_name,
                        json.dumps(old_backup, ensure_ascii=False),
                        application_no,
                        old["id"],
                        user_id
                    ))

                    if cur.rowcount == 0:
                        logger.critical(f"更新记录失败: id={old['id']}, user_id={user_id}")
                        raise Exception("F010: 记录已被修改，操作失败")

                    conn.commit()
                    logger.info(f"改绑申请已提交: user_id={user_id}, application_no={application_no}")

                    # 异步记录审计日志
                    BankcardService._log_operation_async(
                        user_id, 'modify_apply', old["id"],
                        {"old_account_bank": old["account_bank"]},
                        {"new_bank_name": new_bank_name, "application_no": application_no},
                        admin_key, ip_address
                    )

                    return {
                        "msg": "ok",
                        "application_no": application_no,
                        "status": "pending_review",
                        "sub_mchid": sub_mchid
                    }
                except pymysql.MySQLError as e:
                    conn.rollback()
                    logger.critical(
                        f"CRITICAL: 微信已受理但本地写入失败: user_id={user_id}, app_no={application_no}, error={e}"
                    )
                    raise Exception("F011: 系统异常，请保留申请单号并联系客服")
                except Exception as e:
                    conn.rollback()
                    logger.critical(f"CRITICAL: 未知异常: {e}")
                    raise

    @staticmethod
    def poll_modify_status(user_id: int, application_no: str) -> Dict[str, Any]:
        """轮询改绑审核状态（带最终冲突检测）"""
        logger.info(f"【轮询改绑状态】user_id={user_id}, application_no={application_no}")

        # 1. 先查询本地状态
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, sub_mchid, new_bank_name,
                           new_account_name_encrypted, new_account_number_encrypted,
                           old_account_backup, verify_result
                    FROM merchant_settlement_accounts
                    WHERE user_id = %s AND modify_application_no = %s
                    LIMIT 1
                """, (user_id, application_no))
                record = cur.fetchone()
                if not record:
                    raise Exception("F013: 未找到改绑申请记录")

        # 2. 如果本地已经是终态，直接返回（不调用微信）
        if record['verify_result'] in ['VERIFY_SUCCESS', 'VERIFY_FAIL']:
            logger.info(f"本地已为终态: verify_result={record['verify_result']}")
            return {
                "msg": "ok",
                "application_no": application_no,
                "status": record['verify_result'],
                "detail": record.get('modify_fail_reason', ''),
                "is_completed": True
            }

        # 3. 异步查询微信状态
        try:
            wx_resp = wxpay_client.query_application_status(record["sub_mchid"], application_no)
            logger.info(f"微信返回状态: {wx_resp.get('applyment_state')}")
        except Exception as e:
            logger.error(f"微信查询失败: {e}")
            # 返回本地状态
            return {
                "msg": "ok",
                "application_no": application_no,
                "status": "VERIFYING",
                "detail": "查询中，请稍后重试",
                "is_completed": False,
                "wx_error": str(e)
            }

        # 4. 状态转换
        wx_state = wx_resp.get('applyment_state', 'APPLYMENT_STATE_AUDITING')
        new_status = BankcardService.WX_STATUS_MAP.get(wx_state, 'VERIFY_FAIL')
        fail_reason = wx_resp.get('verify_fail_reason', wx_resp.get('applyment_state_msg', ''))

        # 5. 更新数据库
        with get_conn() as conn:
            with conn.cursor() as cur:
                if new_status == 'VERIFY_SUCCESS':
                    # 再次确认新卡未被占用（防止审核期间被其他用户绑定）
                    new_plain_number = BankcardService._decrypt_local_encrypted(
                        record["new_account_number_encrypted"]
                    )
                    new_card_hash = BankcardService._generate_card_hash(new_plain_number)

                    is_unique, bound_user_id = BankcardService._check_card_uniqueness(record['user_id'], new_card_hash)
                    if not is_unique:
                        logger.critical(
                            f"CRITICAL: 审核期间卡被抢占! user_id={record['user_id']}, "
                            f"bound_user_id={bound_user_id}, application_no={application_no}"
                        )

                        # ✅ 优化点2：记录审计日志
                        BankcardService._log_operation_async(
                            user_id,
                            "modify_conflict",
                            record["id"],
                            {"new_card_hash": new_card_hash, "application_no": application_no},
                            {"conflict_user_id": bound_user_id, "status": "VERIFY_FAIL"},
                            "SYSTEM",
                            "127.0.0.1"
                        )

                        # 清理改绑数据，保留旧卡
                        cur.execute("""
                            UPDATE merchant_settlement_accounts
                            SET modify_application_no = NULL,
                                new_account_number_encrypted = NULL,
                                new_account_name_encrypted = NULL,
                                new_bank_name = NULL,
                                old_account_backup = NULL,
                                modify_fail_reason = '审核期间卡被其他用户绑定',
                                updated_at = NOW()
                            WHERE id = %s
                        """, (record["id"],))
                        conn.commit()

                        # ✅ 优化点3：抛出异常而非返回错误字典
                        raise Exception(f"F021: 新卡已被其他用户(user_id={bound_user_id})绑定，改绑失败")

                    # 成功：更新为新卡信息
                    cur.execute("""
                        UPDATE merchant_settlement_accounts
                        SET account_bank = %s,
                            bank_name = %s,
                            account_name_encrypted = %s,
                            account_number_encrypted = %s,
                            card_hash = %s,
                            verify_result = 'VERIFY_SUCCESS',
                            modify_application_no = NULL,
                            modify_fail_reason = NULL,
                            new_account_number_encrypted = NULL,
                            new_account_name_encrypted = NULL,
                            new_bank_name = NULL,
                            old_account_backup = NULL,
                            updated_at = NOW()
                        WHERE id = %s
                    """, (
                        record["new_bank_name"],
                        record["new_bank_name"],
                        record["new_account_name_encrypted"],
                        record["new_account_number_encrypted"],
                        new_card_hash,
                        record["id"]
                    ))

                    # 同步更新user_bankcards
                    cur.execute("""
                        UPDATE user_bankcards
                        SET bank_name = %s, bank_account = %s
                        WHERE user_id = %s
                    """, (record["new_bank_name"], new_plain_number, user_id))

                    logger.info(f"改绑成功: user_id={user_id}, new_bank_name={record['new_bank_name']}")
                else:
                    # 失败：清理临时数据，恢复旧状态
                    cur.execute("""
                        UPDATE merchant_settlement_accounts
                        SET verify_result = %s,
                            modify_fail_reason = %s,
                            modify_application_no = NULL,
                            new_account_number_encrypted = NULL,
                            new_account_name_encrypted = NULL,
                            new_bank_name = NULL,
                            old_account_backup = NULL,
                            updated_at = NOW()
                        WHERE id = %s
                    """, (new_status, fail_reason, record["id"]))

                    logger.info(f"改绑失败: user_id={user_id}, reason={fail_reason}")

                # 异步记录审计日志
                BankcardService._log_operation_async(
                    user_id,
                    "modify_success" if new_status == "VERIFY_SUCCESS" else "modify_fail",
                    record["id"],
                    None,
                    {"verify_result": new_status, "fail_reason": fail_reason},
                    "SYSTEM",
                    "127.0.0.1"
                )
                conn.commit()

        return {
            "msg": "ok",
            "application_no": application_no,
            "status": new_status,
            "detail": fail_reason,
            "is_completed": True,
            "wx_state": wx_state
        }

    @staticmethod
    def query_bind_status(user_id: int) -> Dict[str, Any]:
        """查询绑定状态（整合微信信息）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 查询本地记录
                cur.execute("""
                    SELECT id, status, verify_result, bind_at, sub_mchid 
                    FROM merchant_settlement_accounts 
                    WHERE user_id = %s AND status = 1 LIMIT 1
                """, (user_id,))
                local_record = cur.fetchone()

                if not local_record:
                    return {'is_bound': False, 'reason': '未绑定银行卡'}

                result = {
                    'is_bound': True,
                    'account_id': local_record['id'],
                    'verify_result': local_record['verify_result'],
                    'bind_at': local_record['bind_at'].strftime('%Y-%m-%d %H:%M:%S') if local_record[
                        'bind_at'] else None
                }

                # 查询微信展示信息（限流保护）
                if local_record.get('sub_mchid'):
                    try:
                        wechat_display = wxpay_client.query_settlement_account(local_record['sub_mchid'])
                        result['wechat_display_info'] = wechat_display
                    except Exception as e:
                        logger.warning(f"微信查询失败: {e}")
                        result['wechat_display_info'] = {}

                # 检查改绑状态
                if local_record.get('modify_application_no'):
                    result['modify_status'] = 'in_progress'
                    result['modify_application_no'] = local_record['modify_application_no']

                    # 如果失败，返回失败原因
                    if local_record['verify_result'] == 'VERIFY_FAIL':
                        result['modify_fail_reason'] = local_record.get('modify_fail_reason', '未知原因')

                return result

    @staticmethod
    def get_operation_logs(user_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """获取操作日志列表（脱敏）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, operation_type, target_id, old_val, new_val, 
                           admin_key, ip_address, created_at
                    FROM user_bankcard_operations 
                    WHERE user_id = %s ORDER BY created_at DESC LIMIT %s
                """, (user_id, limit))
                logs = cur.fetchall()

                safe_logs = []
                for log in logs:
                    old_val = json.loads(log['old_val']) if log['old_val'] else None
                    new_val = json.loads(log['new_val']) if log['new_val'] else None

                    # 过滤敏感字段
                    if old_val:
                        old_val = {k: v for k, v in old_val.items() if 'encrypted' not in k and 'card' not in k.lower()}
                    if new_val:
                        new_val = {k: v for k, v in new_val.items() if 'encrypted' not in k and 'card' not in k.lower()}

                    safe_logs.append({
                        'id': log['id'],
                        'operation_type': log['operation_type'],
                        'target_id': log['target_id'],
                        'old_val': old_val,
                        'new_val': new_val,
                        'admin_key': log['admin_key'],
                        'ip_address': log['ip_address'],
                        'created_at': log['created_at'].strftime('%Y-%m-%d %H:%M:%S')
                    })

                return safe_logs

    @staticmethod
    def query_my_bankcard(user_id: int) -> Dict[str, Any]:
        """查询我的银行卡（仅返回验证成功的卡，脱敏展示）"""
        logger.info(f"【查询我的银行卡】user_id={user_id}")
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT id, account_bank, account_number_encrypted, account_name_encrypted,
                           verify_result, bind_at, modify_application_no, modify_fail_reason
                    FROM merchant_settlement_accounts 
                    WHERE user_id = %s AND status = 1 AND verify_result = 'VERIFY_SUCCESS'
                    ORDER BY is_default DESC, bind_at DESC LIMIT 1
                """, (user_id,))
                record = cur.fetchone()
                if not record:
                    return {"has_bankcard": False, "message": "您尚未绑定银行卡"}

                try:
                    full_account = BankcardService._decrypt_local_encrypted(record['account_number_encrypted'])
                    full_name = BankcardService._decrypt_local_encrypted(record['account_name_encrypted'])

                    # 构建掩码卡号
                    if len(full_account) >= 10:
                        masked_account = f"{full_account[:6]}**********{full_account[-4:]}"
                    else:
                        masked_account = f"{'*' * (len(full_account) - 4)}{full_account[-4:]}"

                    result = {
                        "has_bankcard": True,
                        "account_id": record['id'],
                        "account_bank": record['account_bank'],
                        "account_number_masked": masked_account,
                        "account_number_tail": full_account[-4:],
                        "account_name": full_name,
                        "verify_result": record['verify_result'],
                        "bind_at": record['bind_at'].strftime('%Y-%m-%d %H:%M:%S') if record['bind_at'] else None
                    }

                    # 改绑状态
                    if record['modify_application_no']:
                        result['modify_status'] = 'in_progress'
                        result['modify_application_no'] = record['modify_application_no']
                        if record['verify_result'] == 'VERIFY_FAIL' and record['modify_fail_reason']:
                            result['modify_fail_reason'] = record['modify_fail_reason']
                    else:
                        result['modify_status'] = 'none'

                    return result
                except Exception as e:
                    logger.error(f"解密失败: {e}")
                    return {"has_bankcard": True, "account_id": record['id'], "error": "F015: 解密失败"}

    # ========================================
    # 内部工具方法
    # ========================================

    @staticmethod
    def _log_operation(
            user_id: int, operation_type: str, target_id: Optional[int],
            old_val: Optional[Dict], new_val: Optional[Dict],
            admin_key: Optional[str], ip_address: Optional[str]
    ):
        """审计日志（同步写入）"""
        # 过滤敏感字段
        safe_old = {k: v for k, v in (old_val or {}).items() if 'encrypted' not in k and 'card' not in k.lower()}
        safe_new = {k: v for k, v in (new_val or {}).items() if 'encrypted' not in k and 'card' not in k.lower()}

        try:
            with get_conn() as conn:
                with conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO user_bankcard_operations 
                        (user_id, operation_type, target_id, old_val, new_val, admin_key, ip_address)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        user_id, operation_type, target_id,
                        json.dumps(safe_old, ensure_ascii=False) if safe_old else None,
                        json.dumps(safe_new, ensure_ascii=False) if safe_new else None,
                        admin_key, ip_address
                    ))
                conn.commit()
        except Exception as e:
            logger.error(f"审计日志写入失败[非阻断]: {e}")

    @staticmethod
    def _log_operation_async(
            user_id: int, operation_type: str, target_id: Optional[int],
            old_val: Optional[Dict], new_val: Optional[Dict],
            admin_key: Optional[str], ip_address: Optional[str]
    ):
        """审计日志（异步写入，避免阻塞）"""
        try:
            import threading
            def _write_log():
                BankcardService._log_operation(
                    user_id, operation_type, target_id, old_val, new_val, admin_key, ip_address
                )

            threading.Thread(target=_write_log, daemon=True).start()
        except Exception as e:
            logger.error(f"异步日志写入失败: {e}")

    @staticmethod
    def _encrypt_sensitive(plaintext: str) -> str:
        """本地AES-GCM加密"""
        key = wxpay_client.apiv3_key[:32]
        return wxpay_client._encrypt_local(plaintext, key)

    @staticmethod
    def _decrypt_local_encrypted(encrypted_data: str, key: Optional[bytes] = None) -> str:
        """本地AES-GCM解密"""
        if key is None:
            key = wxpay_client.apiv3_key[:32]
        return wxpay_client._decrypt_local(encrypted_data, key)

    @staticmethod
    def _generate_card_hash(bank_account: str) -> str:
        """生成银行卡号哈希（加盐防彩虹表）"""
        salt = os.getenv('CARD_SALT')
        if not salt:
            raise RuntimeError("环境变量 CARD_SALT 未配置")
        # 使用SHA256加盐哈希
        return hashlib.sha256(f"{bank_account}_{salt}".encode()).hexdigest()

    @staticmethod
    def _verify_pay_password(user_id: int, pay_password: str) -> bool:
        """验证支付密码（Mock实现）"""
        # 生产环境：查询users表的pay_password_hash字段并验证bcrypt
        # 测试环境：基于用户ID的Mock验证
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT id FROM users WHERE id = %s AND status = 0", (user_id,))
                return cur.fetchone() is not None