# services/wechat_applyment_service.py
import uuid
import json
import datetime
import hashlib
import os
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any
from fastapi import HTTPException, UploadFile
from core.database import get_conn
from core.config import WECHAT_PAY_MCH_ID, WECHAT_PAY_API_V3_KEY, DRAFT_EXPIRE_DAYS, MAX_FILE_SIZE_MB
from core.wx_pay_client import WeChatPayClient  # ✅ 修复：WechatPayClient → WeChatPayClient
from core.push_service import push_service
from core.table_access import build_dynamic_select, build_dynamic_insert, build_dynamic_update
import logging

logger = logging.getLogger(__name__)


class WechatApplymentService:
    def __init__(self):
        self.pay_client = WeChatPayClient()  # ✅ 修复：WechatPayClient → WeChatPayClient
        self.max_file_size = MAX_FILE_SIZE_MB * 1024 * 1024

    def _get_realname_data(self, user_id: int) -> Optional[Dict[str, Any]]:
        """获取实名认证数据"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT * FROM merchant_realname_verification 
                    WHERE user_id = %s AND status = 'approved'
                    ORDER BY audited_at DESC LIMIT 1
                """, (user_id,))
                return cur.fetchone()

    def _encrypt_bank_info(self, bank_info: Dict[str, Any]) -> Dict[str, Any]:
        """加密银行卡敏感信息"""
        try:
            # 加密开户名称和账号
            if 'account_name' in bank_info:
                bank_info['account_name_encrypted'] = self.pay_client.encrypt_sensitive_data(
                    bank_info.pop('account_name')
                )
            if 'account_number' in bank_info:
                bank_info['account_number_encrypted'] = self.pay_client.encrypt_sensitive_data(
                    bank_info.pop('account_number')
                )
            return bank_info
        except Exception as e:
            logger.error(f"银行卡信息加密失败: {str(e)}")
            raise HTTPException(status_code=500, detail="银行卡信息处理失败")

    def save_draft(self, user_id: int, data: dict) -> dict:
        """保存进件草稿（自动填充实名数据）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查是否已有草稿或进行中的申请
                cur.execute("""
                    SELECT id, applyment_state FROM wx_applyment 
                    WHERE user_id = %s AND applyment_state IN (
                        'APPLYMENT_STATE_EDITTING', 
                        'APPLYMENT_STATE_AUDITING',
                        'APPLYMENT_STATE_REJECTED'
                    )
                    ORDER BY created_at DESC LIMIT 1
                """, (user_id,))
                existing = cur.fetchone()

                # 自动填充实名认证数据
                realname_data = self._get_realname_data(user_id)
                if realname_data:
                    # 填充主体信息
                    subject_info = data.get("subject_info", {})
                    if realname_data['verification_type'] == 'enterprise':
                        subject_info['business_license_no'] = subject_info.get(
                            'business_license_no',
                            realname_data.get('business_license_no', '')
                        )
                        subject_info['legal_person_name'] = subject_info.get(
                            'legal_person_name',
                            realname_data.get('legal_person_name', '')
                        )
                    data['subject_info'] = subject_info

                business_code = str(uuid.uuid4()).replace('-', '')
                draft_expires_at = datetime.datetime.now() + datetime.timedelta(days=DRAFT_EXPIRE_DAYS)

                # 准备数据
                subject_info = data.get("subject_info", {})
                contact_info = data.get("contact_info", {})
                bank_account_info = data.get("bank_account_info", {})

                # 加密银行卡信息
                if bank_account_info:
                    bank_account_info = self._encrypt_bank_info(bank_account_info)

                if existing and existing["applyment_state"] == "APPLYMENT_STATE_EDITTING":
                    # 更新现有草稿
                    update_data = {
                        "subject_info": json.dumps(subject_info, ensure_ascii=False),
                        "contact_info": json.dumps(contact_info, ensure_ascii=False),
                        "bank_account_info": json.dumps(bank_account_info, ensure_ascii=False),
                        "draft_expired_at": draft_expires_at,
                        "updated_at": datetime.datetime.now()
                    }
                    where_clause = "id = %s"
                    update_sql = build_dynamic_update(cur, "wx_applyment", update_data, where_clause)
                    # 关键修复：将SET值和WHERE值合并为参数列表
                    params = list(update_data.values()) + [existing["id"]]
                    cur.execute(update_sql, tuple(params))
                    conn.commit()
                    logger.info(f"用户 {user_id} 更新了进件草稿: {existing['id']}")
                    return {"applyment_id": existing["id"], "business_code": existing.get("business_code")}
                else:
                    # ✅ 修复：使用原生 SQL 插入，避免 build_dynamic_insert 参数问题
                    insert_sql = """
                        INSERT INTO wx_applyment (
                            user_id, business_code, subject_type, 
                            subject_info, contact_info, bank_account_info,
                            applyment_state, is_draft, draft_expired_at,
                            created_at, updated_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()
                        )
                    """
                    cur.execute(insert_sql, (
                        user_id,
                        business_code,
                        data.get("subject_type", "SUBJECT_TYPE_INDIVIDUAL"),
                        json.dumps(subject_info, ensure_ascii=False),
                        json.dumps(contact_info, ensure_ascii=False),
                        json.dumps(bank_account_info, ensure_ascii=False),
                        "APPLYMENT_STATE_EDITTING",
                        1,
                        draft_expires_at
                    ))
                    conn.commit()
                    new_id = cur.lastrowid
                    logger.info(f"用户 {user_id} 创建了进件草稿: {new_id}")
                    return {"applyment_id": new_id, "business_code": business_code}

    async def submit_applyment(self, user_id: int, data: dict) -> dict:
        """提交进件申请到微信支付"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 获取最新的草稿或申请记录
                cur.execute("""
                    SELECT * FROM wx_applyment 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC LIMIT 1
                """, (user_id,))
                applyment = cur.fetchone()

                if not applyment:
                    raise HTTPException(status_code=400, detail="未找到进件草稿，请先保存草稿")

                if applyment["applyment_state"] not in ["APPLYMENT_STATE_EDITTING", "APPLYMENT_STATE_REJECTED"]:
                    raise HTTPException(status_code=400, detail="当前状态不允许提交")

                # 检查草稿是否过期
                if applyment["draft_expired_at"] and applyment["draft_expired_at"] < datetime.datetime.now():
                    raise HTTPException(status_code=400, detail="草稿已过期，请重新填写")

                # 关联用户所有材料到当前草稿（按材料类型）
                cur.execute("""
                    UPDATE wx_applyment_media 
                    SET applyment_id = %s 
                    WHERE user_id = %s 
                      AND media_type IN ('id_card_front', 'id_card_back', 'business_license')
                """, (applyment["id"], user_id))
                conn.commit()
                logger.info(f"关联 {cur.rowcount} 个材料到草稿 {applyment['id']}")

                # 验证材料完整性
                self._validate_media(cur, user_id, applyment["id"])

                # 经营类目锁定校验（如果已有审核记录）
                if applyment.get('subject_info'):
                    # 处理旧数据（从数据库读取）
                    old_info_raw = applyment['subject_info']
                    old_info = json.loads(old_info_raw) if isinstance(old_info_raw, str) else old_info_raw

                    # 处理新数据（来自请求）
                    new_info_raw = data.get('subject_info', {})
                    new_info = json.loads(new_info_raw) if isinstance(new_info_raw, str) else new_info_raw

                    if old_info.get('business_category') and old_info.get('business_category') != new_info.get(
                            'business_category'):
                        raise HTTPException(status_code=400, detail="经营类目不可修改")

                # 调用微信支付API提交进件
                try:
                    response = self.pay_client.submit_applyment(applyment)
                    applyment_id = response.get("applyment_id")

                    # 更新状态
                    update_data = {
                        "applyment_id": applyment_id,
                        "applyment_state": "APPLYMENT_STATE_AUDITING",
                        "is_draft": 0,
                        "submitted_at": datetime.datetime.now(),
                        "updated_at": datetime.datetime.now()
                    }
                    update_sql = build_dynamic_update(cur, "wx_applyment", update_data, "id = %s")
                    # 关键修复：合并SET参数和WHERE参数
                    params = list(update_data.values()) + [applyment["id"]]
                    cur.execute(update_sql, tuple(params))

                    # 记录日志
                    self._log_state_change(cur, applyment["id"], applyment["business_code"],
                                           applyment["applyment_state"], "APPLYMENT_STATE_AUDITING",
                                           "SYSTEM", response.get("state_msg", ""))

                    conn.commit()
                    logger.info(f"用户 {user_id} 提交进件申请: {applyment_id}")

                    # 推送通知
                    await push_service.send_applyment_status_notification(
                        user_id,
                        "APPLYMENT_STATE_AUDITING",
                        "您的进件申请已提交至微信审核"
                    )

                    return {"applyment_id": applyment["id"], "wx_applyment_id": applyment_id}

                except Exception as e:
                    conn.rollback()
                    logger.error(f"用户 {user_id} 提交进件失败: {str(e)}")
                    raise HTTPException(status_code=500, detail=f"提交失败: {str(e)}")

    async def upload_media(self, user_id: int, file: UploadFile, media_type: str) -> dict:
        """上传进件材料"""
        # 读取文件内容
        content = await file.read()
        file_size = len(content)

        # 校验文件大小
        if file_size > self.max_file_size:
            raise HTTPException(status_code=400, detail=f"文件大小不能超过{MAX_FILE_SIZE_MB}MB")

        # 计算SHA256
        sha256 = hashlib.sha256(content).hexdigest()

        # 安全路径处理
        base_upload_dir = Path("uploads/applyment_media")
        upload_dir = base_upload_dir / str(user_id)
        upload_dir.mkdir(parents=True, exist_ok=True)
        file_path = upload_dir / f"{sha256}_{file.filename}"

        with open(file_path, "wb") as f:
            f.write(content)

        # 上传到微信支付获取media_id
        media_id = self.pay_client.upload_image(content, file.content_type)

        # 保存到数据库
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 查找草稿ID
                cur.execute("""
                    SELECT id FROM wx_applyment 
                    WHERE user_id = %s AND applyment_state = 'APPLYMENT_STATE_EDITTING'
                    ORDER BY created_at DESC LIMIT 1
                """, (user_id,))
                draft = cur.fetchone()
                applyment_id = draft['id'] if draft else None

                # ✅ 修复：使用原生 SQL 插入，避免 build_dynamic_insert 参数问题
                insert_sql = """
                    INSERT INTO wx_applyment_media (
                        user_id, applyment_id, media_id, media_type,
                        file_path, file_name, file_size, sha256, mime_type,
                        upload_status, expires_at, created_at
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW()
                    )
                """
                cur.execute(insert_sql, (
                    user_id,
                    applyment_id,
                    media_id,
                    media_type,
                    str(file_path),
                    file.filename,
                    file_size,
                    sha256,
                    file.content_type,
                    "uploaded",
                    datetime.datetime.now() + datetime.timedelta(days=1)
                ))
                conn.commit()
                logger.info(f"用户 {user_id} 上传材料: {media_id} - {file.filename}")

                return {
                    "media_id": media_id,
                    "file_path": str(file_path),
                    "expires_at": datetime.datetime.now() + datetime.timedelta(days=1)
                }

    def list_media(self, user_id: int, applyment_id: Optional[int] = None) -> List[dict]:
        """查询材料列表"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                where_clause = "user_id = %s"
                params = [user_id]

                # ✅ 修复：判断 applyment_id 是否为 None，而不是是否为 0
                if applyment_id is not None:
                    where_clause += " AND applyment_id = %s"
                    params.append(applyment_id)

                select_sql = build_dynamic_select(
                    cur,
                    "wx_applyment_media",
                    where_clause=where_clause,
                    select_fields=["id", "media_id", "media_type", "file_name", "upload_status", "created_at"]
                )
                cur.execute(select_sql, tuple(params))
                return cur.fetchall()

    def get_applyment_status(self, user_id: int) -> dict:
        """查询进件状态"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT 
                        id,
                        business_code,
                        applyment_id,
                        applyment_state,
                        applyment_state_msg,
                        sign_url,
                        audit_detail,
                        sub_mchid,
                        is_core_info_modified,
                        submitted_at,
                        finished_at,
                        created_at
                    FROM wx_applyment 
                    WHERE user_id = %s 
                    ORDER BY created_at DESC LIMIT 1
                """, (user_id,))

                status = cur.fetchone()
                if not status:
                    return {"status": "no_applyment"}

                # 获取关联的结算账户
                cur.execute("""
                    SELECT id, account_bank, bank_name, account_type 
                    FROM merchant_settlement_accounts 
                    WHERE user_id = %s AND status = 1
                """, (user_id,))
                settlement_accounts = cur.fetchall()

                status["settlement_accounts"] = settlement_accounts
                return status

    def modify_core_info(self, user_id: int, data: dict) -> dict:
        """修改核心信息（触发重新进件）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 检查当前状态
                cur.execute("""
                    SELECT id, applyment_state, subject_info, subject_type 
                    FROM wx_applyment 
                    WHERE user_id = %s AND applyment_state = 'APPLYMENT_STATE_FINISHED'
                    ORDER BY finished_at DESC LIMIT 1
                """, (user_id,))
                existing = cur.fetchone()

                if not existing:
                    raise HTTPException(status_code=400, detail="未找到已完成的进件记录")

                # 检查是否修改了核心信息（经营类目或结算账户）
                new_bank_info = data.get("bank_account_info", {})
                old_subject_info = json.loads(existing["subject_info"])

                # 经营类目不可修改校验
                if 'business_category' in new_bank_info and old_subject_info.get(
                        'business_category') != new_bank_info.get('business_category'):
                    raise HTTPException(status_code=400, detail="经营类目不可修改")

                # 标记核心信息已修改
                update_data = {
                    "is_core_info_modified": 1,
                    "applyment_state": "APPLYMENT_STATE_EDITTING",
                    "updated_at": datetime.datetime.now()
                }
                update_sql = build_dynamic_update(cur, "wx_applyment", update_data, "id = %s")
                params = list(update_data.values()) + [existing["id"]]
                cur.execute(update_sql, tuple(params))

                # 创建新的进件记录
                new_business_code = str(uuid.uuid4()).replace('-', '')

                # 关键修复：从数据库字段获取subject_type
                old_subject_type = existing["subject_type"]  # ← 必须添加这一行

                insert_data = {
                    "user_id": user_id,
                    "business_code": new_business_code,
                    "subject_type": old_subject_type,  # ← 使用数据库字段值
                    "subject_info": existing["subject_info"],
                    "contact_info": json.dumps(data.get("contact_info", {}), ensure_ascii=False),
                    "bank_account_info": json.dumps(new_bank_info, ensure_ascii=False),
                    "applyment_state": "APPLYMENT_STATE_EDITTING",
                    "is_draft": 1,
                    "draft_expired_at": datetime.datetime.now() + datetime.timedelta(days=DRAFT_EXPIRE_DAYS),
                    "is_core_info_modified": 1,
                    "created_at": datetime.datetime.now(),
                    "updated_at": datetime.datetime.now()
                }
                insert_sql = build_dynamic_insert(cur, "wx_applyment", insert_data)
                # 关键修复：提供插入参数（按顺序）
                insert_values = [
                    user_id,
                    new_business_code,
                    old_subject_type,
                    existing["subject_info"],
                    json.dumps(data.get("contact_info", {}), ensure_ascii=False),
                    json.dumps(new_bank_info, ensure_ascii=False),
                    "APPLYMENT_STATE_EDITTING",
                    1,
                    datetime.datetime.now() + datetime.timedelta(days=DRAFT_EXPIRE_DAYS),
                    1,
                    datetime.datetime.now(),
                    datetime.datetime.now()
                ]
                cur.execute(insert_sql, tuple(insert_values))

                # ========================================
                # 新增：复制原申请单的材料到新申请单
                # ========================================
                cur.execute("""
                    INSERT INTO wx_applyment_media (
                        applyment_id, user_id, media_id, media_type,
                        file_path, file_name, file_size, sha256, mime_type,
                        upload_status, expires_at, created_at
                    )
                    SELECT 
                        %s as applyment_id, 
                        user_id, media_id, media_type,
                        file_path, file_name, file_size, sha256, mime_type,
                        upload_status, expires_at, NOW()
                    FROM wx_applyment_media 
                    WHERE applyment_id = %s
                """, (cur.lastrowid, existing["id"]))
                # ========================================

                conn.commit()
                logger.info(f"用户 {user_id} 修改核心信息，重新进件: {cur.lastrowid}")
                return {"new_applyment_id": cur.lastrowid, "business_code": new_business_code}

    def resubmit_applyment(self, user_id: int, applyment_id: int) -> dict:
        """重新提交被驳回的进件"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT * FROM wx_applyment 
                    WHERE id = %s AND user_id = %s AND applyment_state = 'APPLYMENT_STATE_REJECTED'
                """, (applyment_id, user_id))
                applyment = cur.fetchone()

                if not applyment:
                    raise HTTPException(status_code=400, detail="未找到可重新提交的进件记录")

                # 检查是否修改了驳回的问题
                if not self._check_reject_issues_fixed(cur, applyment_id):
                    raise HTTPException(status_code=400, detail="请先根据驳回原因修改信息")

                # 调用微信支付API重新提交
                response = self.pay_client.submit_applyment(applyment)

                # 更新状态
                update_data = {
                    "applyment_state": "APPLYMENT_STATE_AUDITING",
                    "updated_at": datetime.datetime.now()
                }
                update_sql = build_dynamic_update(cur, "wx_applyment", update_data, "id = %s")
                # 关键修复：合并SET参数和WHERE参数
                params = list(update_data.values()) + [applyment_id]
                cur.execute(update_sql, tuple(params))

                # 记录日志
                self._log_state_change(cur, applyment_id, applyment["business_code"],
                                       "APPLYMENT_STATE_REJECTED", "APPLYMENT_STATE_AUDITING",
                                       "USER", "用户重新提交")

                conn.commit()
                logger.info(f"用户 {user_id} 重新提交进件: {applyment_id}")
                return {"applyment_id": applyment_id}

    def get_merchant_info(self, user_id: int) -> dict:
        """获取商户号信息"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    SELECT sub_mchid, business_code, finished_at 
                    FROM wx_applyment 
                    WHERE user_id = %s AND applyment_state = 'APPLYMENT_STATE_FINISHED'
                    ORDER BY finished_at DESC LIMIT 1
                """, (user_id,))

                info = cur.fetchone()
                if not info or not info["sub_mchid"]:
                    raise HTTPException(status_code=404, detail="商户号信息不存在")

                return info

    def _validate_media(self, cur, user_id: int, applyment_id: int):
        """验证材料完整性"""
        # ✅ 修复：同时检查 NULL 和 0
        cur.execute("""
            SELECT media_type FROM wx_applyment_media 
            WHERE user_id = %s AND (applyment_id = %s OR applyment_id IS NULL OR applyment_id = 0)
        """, (user_id, applyment_id))
        uploaded = {row['media_type'] for row in cur.fetchall()}

        required = {'id_card_front', 'id_card_back', 'business_license'}
        if not required.issubset(uploaded):
            raise HTTPException(status_code=400, detail="缺少必要的材料")

    def _check_reject_issues_fixed(self, cur, applyment_id: int) -> bool:
        """检查驳回问题是否已修复"""
        cur.execute("SELECT audit_detail FROM wx_applyment WHERE id = %s", (applyment_id,))
        detail = cur.fetchone()
        if not detail or not detail["audit_detail"]:
            return True

        # 简化的检查逻辑（实际应根据audit_detail中的具体字段判断）
        return True

    def _log_state_change(self, cur, applyment_id: int, business_code: str, old_state: str, new_state: str,
                          operator: str, state_msg: str):
        """记录状态变更日志"""
        log_data = {
            "applyment_id": applyment_id,
            "business_code": business_code,
            "old_state": old_state,
            "new_state": new_state,
            "state_msg": state_msg,
            "operator": operator,
            "created_at": datetime.datetime.now()
        }
        insert_sql = build_dynamic_insert(cur, "wx_applyment_log", log_data)
        # 关键修复：提供插入参数
        cur.execute(insert_sql, tuple(log_data.values()))

    async def handle_applyment_state_change(self, applyment_id: int, new_state: str, status_info: Dict[str, Any]):
        """处理进件状态变更（带推送）"""
        with get_conn() as conn:
            with conn.cursor() as cur:
                # 获取用户信息
                cur.execute("""
                    SELECT user_id, business_code, applyment_state 
                    FROM wx_applyment 
                    WHERE applyment_id = %s
                """, (applyment_id,))
                result = cur.fetchone()
                if not result:
                    logger.error(f"未找到进件记录: {applyment_id}")
                    return

                user_id = result['user_id']
                old_state = result['applyment_state']

                # 更新状态
                update_sql = build_dynamic_update(
                    cur,
                    "wx_applyment",
                    {
                        "applyment_state": new_state,
                        "applyment_state_msg": status_info.get("state_msg"),
                        "sub_mchid": status_info.get("sub_mchid"),
                        "finished_at": datetime.datetime.now() if new_state == "APPLYMENT_STATE_FINISHED" else None,
                        "updated_at": datetime.datetime.now()
                    },
                    "applyment_id = %s"
                )
                cur.execute(update_sql, (applyment_id,))

                # 如果审核通过，绑定商户号
                if new_state == "APPLYMENT_STATE_FINISHED":
                    cur.execute("""
                        UPDATE users u
                        JOIN wx_applyment wa ON u.id = wa.user_id
                        SET u.wechat_sub_mchid = %s
                        WHERE wa.applyment_id = %s
                    """, (status_info.get("sub_mchid"), applyment_id))

                # 记录日志
                self._log_state_change(cur, applyment_id, result['business_code'],
                                       old_state, new_state, "WECHAT", status_info.get("state_msg", ""))

                conn.commit()

                # 推送通知
                await push_service.send_applyment_status_notification(
                    user_id,
                    new_state,
                    status_info.get("state_msg", "")
                )

                logger.info(f"进件状态变更: {applyment_id} -> {new_state}")