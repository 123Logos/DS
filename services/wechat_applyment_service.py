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

    def _extract_id_card_periods(self, subject_info: Any) -> tuple[Optional[str], Optional[str]]:
        """从 subject_info 中提取身份证有效期，允许字符串 JSON 输入。"""
        info = subject_info or {}
        if isinstance(info, str):
            try:
                info = json.loads(info)
            except Exception:
                info = {}

        identity_info = info.get("identity_info") or {}
        if isinstance(identity_info, str):
            try:
                identity_info = json.loads(identity_info)
            except Exception:
                identity_info = {}

        id_card_info = identity_info.get("id_card_info") or {}
        if isinstance(id_card_info, str):
            try:
                id_card_info = json.loads(id_card_info)
            except Exception:
                id_card_info = {}

        begin = (
            id_card_info.get("card_period_begin")
            or identity_info.get("card_period_begin")
            or info.get("card_period_begin")
        )
        end = (
            id_card_info.get("card_period_end")
            or identity_info.get("card_period_end")
            or info.get("card_period_end")
        )

        def _normalize(val: Any) -> Optional[str]:
            if val is None:
                return None
            text = str(val).strip()
            return text if text else None

        return _normalize(begin), _normalize(end)

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
            logger.error("银行卡信息加密失败: error_type=%s", type(e).__name__)
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
                card_period_begin, card_period_end = self._extract_id_card_periods(subject_info)

                # 加密银行卡信息
                if bank_account_info:
                    bank_account_info = self._encrypt_bank_info(bank_account_info)

                if existing and existing["applyment_state"] == "APPLYMENT_STATE_EDITTING":
                    # 更新现有草稿
                    update_data = {
                        "subject_info": json.dumps(subject_info, ensure_ascii=False),
                        "contact_info": json.dumps(contact_info, ensure_ascii=False),
                        "bank_account_info": json.dumps(bank_account_info, ensure_ascii=False),
                        "card_period_begin": card_period_begin,
                        "card_period_end": card_period_end,
                        "draft_expired_at": draft_expires_at,
                        "updated_at": datetime.datetime.now()
                    }
                    where_clause = "id = %s"
                    update_sql = build_dynamic_update(cur, "wx_applyment", update_data, where_clause)
                    # 关键修复：将SET值和WHERE值合并为参数列表
                    params = list(update_data.values()) + [existing["id"]]
                    cur.execute(update_sql, tuple(params))
                    conn.commit()
                    logger.info("Updated application draft")
                    return {"applyment_id": existing["id"], "business_code": existing.get("business_code")}
                else:
                    # ✅ 修复：使用原生 SQL 插入，避免 build_dynamic_insert 参数问题
                    insert_sql = """
                        INSERT INTO wx_applyment (
                            user_id, business_code, subject_type, 
                            subject_info, contact_info, bank_account_info,
                            card_period_begin, card_period_end,
                            applyment_state, is_draft, draft_expired_at,
                            created_at, updated_at
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW()
                        )
                    """
                    cur.execute(insert_sql, (
                        user_id,
                        business_code,
                        data.get("subject_type", "SUBJECT_TYPE_INDIVIDUAL"),
                        json.dumps(subject_info, ensure_ascii=False),
                        json.dumps(contact_info, ensure_ascii=False),
                        json.dumps(bank_account_info, ensure_ascii=False),
                        card_period_begin,
                        card_period_end,
                        "APPLYMENT_STATE_EDITTING",
                        1,
                        draft_expires_at
                    ))
                    conn.commit()
                    new_id = cur.lastrowid
                    logger.info("Created application draft")
                    return {"applyment_id": new_id, "business_code": business_code}

    async def submit_applyment(self, user_id: int, data: dict, parent_mchid: str = None) -> dict:
        """
        提交进件申请到微信支付
        - 作为二级子商户进件（需要平台已配置服务商资质）
        """
        # 优先使用传入的参数，否则使用配置
        from core.config import WECHAT_PAY_SP_MCH_ID, WECHAT_PAY_SP_APPID

        sp_mchid = parent_mchid or WECHAT_PAY_SP_MCH_ID

        if not sp_mchid:
            raise HTTPException(status_code=400, detail="平台尚未配置微信支付服务商资质，无法为商家进件")

        if not WECHAT_PAY_SP_APPID:
            raise HTTPException(status_code=400, detail="平台尚未配置服务商APPID，无法为商家进件")

        payload_snapshot: dict = {}
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

                # 前端提交的主体类型优先，避免使用过期的草稿值
                applyment["subject_type"] = data.get("subject_type") or applyment.get("subject_type")

                # 关联用户所有材料到当前草稿（按材料类型）
                cur.execute("""
                    UPDATE wx_applyment_media 
                    SET applyment_id = %s 
                    WHERE user_id = %s 
                      AND media_type IN ('id_card_front', 'id_card_back', 'business_license')
                """, (applyment["id"], user_id))
                conn.commit()
                logger.info("Linked application media: count=%s", cur.rowcount)

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

                # 提交前关键字段校验（避免把必填缺失的请求发给微信）
                contact_info_raw = applyment.get("contact_info")
                contact_info = json.loads(contact_info_raw) if isinstance(contact_info_raw, str) else contact_info_raw
                if not contact_info or not contact_info.get("contact_name"):
                    logger.warning(
                        "用户 %s 进件提交前缺少 contact_name，business_code=%s",
                        user_id,
                        applyment.get("business_code"),
                    )
                    raise HTTPException(status_code=400, detail="请填写超级管理员姓名（contact_name）后再提交")

                # 预先构建快照，避免异常分支未定义
                payload_snapshot = {
                    "applyment_db_id": applyment.get("id"),
                    "business_code": applyment.get("business_code"),
                    "subject_type": applyment.get("subject_type"),
                    "has_contact_info": bool(applyment.get("contact_info")),
                    "has_subject_info": bool(applyment.get("subject_info")),
                    "has_bank_account_info": bool(applyment.get("bank_account_info")),
                    "business_info": data.get("business_info") or applyment.get("business_info"),
                    "parent_mchid": WECHAT_PAY_SP_MCH_ID,  # 记录服务商号
                    "platform_appid": WECHAT_PAY_SP_APPID,  # 记录服务商APPID
                }

                # 调用微信支付API提交进件（强制使用服务商模式）
                try:
                    # 前端提交的 business_info 透传给微信；如未提供则回退草稿中的字段
                    business_info_raw = data.get("business_info") or applyment.get("business_info") or {}
                    if isinstance(business_info_raw, str):
                        try:
                            business_info_raw = json.loads(business_info_raw)
                        except Exception:
                            business_info_raw = {}

                    # 解析最新提交的主体信息（包含身份证有效期）
                    incoming_subject_info_raw = data.get("subject_info") or {}
                    incoming_subject_info = (
                        json.loads(incoming_subject_info_raw)
                        if isinstance(incoming_subject_info_raw, str)
                        else incoming_subject_info_raw
                             or {}
                    )
                    incoming_identity_info = incoming_subject_info.get("identity_info") or {}
                    if isinstance(incoming_identity_info, str):
                        try:
                            incoming_identity_info = json.loads(incoming_identity_info)
                        except Exception:
                            incoming_identity_info = {}
                    incoming_id_card_info = incoming_identity_info.get("id_card_info") or {}
                    if isinstance(incoming_id_card_info, str):
                        try:
                            incoming_id_card_info = json.loads(incoming_id_card_info)
                        except Exception:
                            incoming_id_card_info = {}

                    # 从已上传材料回填身份证件 media_id
                    cur.execute(
                        """
                            SELECT media_type, media_id
                            FROM wx_applyment_media
                            WHERE applyment_id = %s AND media_type IN ('id_card_front', 'id_card_back')
                        """,
                        (applyment["id"],),
                    )
                    media_rows = cur.fetchall() or []
                    id_card_media = {row["media_type"]: row["media_id"] for row in media_rows}

                    subject_info_raw = applyment.get("subject_info")
                    subject_info = (
                        json.loads(subject_info_raw)
                        if isinstance(subject_info_raw, str)
                        else subject_info_raw
                             or {}
                    )
                    identity_info = subject_info.get("identity_info") or {}
                    if isinstance(identity_info, str):
                        try:
                            identity_info = json.loads(identity_info)
                        except Exception:
                            identity_info = {}

                    id_card_info = identity_info.get("id_card_info") or {}
                    if id_card_media.get("id_card_front"):
                        id_card_info["id_card_copy"] = id_card_media["id_card_front"]
                    if id_card_media.get("id_card_back"):
                        id_card_info["id_card_national"] = id_card_media["id_card_back"]

                    # 回填身份证有效期：优化优先级（已存在的 > 新传入的 > 兜底）
                    if not id_card_info.get("card_period_begin"):
                        candidate_begin = (
                                id_card_info.get("card_period_begin")  # 已存在的（最高优先级）
                                or incoming_id_card_info.get("card_period_begin")  # 新传入的
                                or subject_info.get("card_period_begin")  # 兜底
                        )
                        if candidate_begin:
                            id_card_info["card_period_begin"] = str(candidate_begin)

                    if not id_card_info.get("card_period_end"):
                        candidate_end = (
                                id_card_info.get("card_period_end")  # 已存在的（最高优先级）
                                or incoming_id_card_info.get("card_period_end")  # 新传入的
                                or subject_info.get("card_period_end")  # 兜底
                        )
                        if candidate_end:
                            id_card_info["card_period_end"] = str(candidate_end)

                    # 前置校验必填项，避免将缺失字段提交至微信
                    if applyment.get("subject_type") == "SUBJECT_TYPE_INDIVIDUAL":
                        missing_period = []
                        if not id_card_info.get("card_period_begin"):
                            missing_period.append("身份证有效期开始时间")
                        if not id_card_info.get("card_period_end"):
                            missing_period.append("身份证有效期结束时间")
                        if missing_period:
                            raise HTTPException(
                                status_code=400,
                                detail="请先填写" + "、".join(missing_period)
                            )

                    if id_card_info:
                        identity_info["id_card_info"] = id_card_info
                        subject_info["identity_info"] = identity_info
                        applyment["subject_info"] = subject_info

                    # 如果仍缺失简称，尝试从主体信息 name/business_name 填充
                    if not business_info_raw.get("merchant_shortname"):
                        subject_info_raw = applyment.get("subject_info")
                        subject_info = json.loads(subject_info_raw) if isinstance(subject_info_raw,
                                                                                  str) else subject_info_raw or {}
                        fallback_shortname = subject_info.get("merchant_shortname") or subject_info.get(
                            "name") or subject_info.get("business_name")
                        if fallback_shortname:
                            business_info_raw["merchant_shortname"] = fallback_shortname

                    if not business_info_raw.get("merchant_shortname"):
                        raise HTTPException(status_code=400, detail="请填写商户简称（merchant_shortname）后再提交")

                    applyment["business_info"] = business_info_raw

                    # ✅ 关键修改：显式构建 payload（参考微信文档）
                    from core.config import WECHAT_PAY_SP_APPID, WECHAT_PAY_SP_MCH_ID, WX_SETTLE_RULE_ID

                    payload = {
                        "business_code": applyment["business_code"],
                        "sp_appid": WECHAT_PAY_SP_APPID,  # 必须：服务商APPID
                        "sp_mchid": WECHAT_PAY_SP_MCH_ID,  # 必须：服务商商户号
                        "sub_mchid": None,  # 微信会返回
                        "subject_type": applyment["subject_type"],
                        "subject_info": subject_info,  # 已处理得很好
                        "contact_info": contact_info,
                        "business_info": business_info_raw,  # 必须包含 merchant_shortname
                        "settlement_info": {  # 新增（强烈建议）
                            "settlement_id": WX_SETTLE_RULE_ID,  # 从 .env 读取
                            "settlement_period": "T+1"
                        }
                    }

                    # ✅ 强制使用服务商模式（is_sub_merchant=True）
                    response = self.pay_client.submit_applyment(payload, is_sub_merchant=True)
                    applyment_id = response.get("applyment_id")

                    card_period_begin = id_card_info.get("card_period_begin")
                    card_period_end = id_card_info.get("card_period_end")

                    # 更新状态（添加服务商相关信息）
                    final_update_data = {
                        "applyment_id": applyment_id,
                        "applyment_state": "APPLYMENT_STATE_AUDITING",
                        "is_draft": 0,
                        "submitted_at": datetime.datetime.now(),
                        "card_period_begin": card_period_begin,
                        "card_period_end": card_period_end,
                        "updated_at": datetime.datetime.now(),
                        "parent_mchid": WECHAT_PAY_SP_MCH_ID,  # 记录服务商号
                    }
                    final_update_sql = build_dynamic_update(cur, "wx_applyment", final_update_data, "id = %s")
                    final_params = list(final_update_data.values()) + [applyment["id"]]
                    cur.execute(final_update_sql, tuple(final_params))

                    # 记录日志
                    self._log_state_change(cur, applyment["id"], applyment["business_code"],
                                           applyment["applyment_state"], "APPLYMENT_STATE_AUDITING",
                                           "SYSTEM", response.get("state_msg", ""))

                    conn.commit()
                    logger.info("提交进件申请成功")

                    # 推送通知
                    await push_service.send_applyment_status_notification(
                        user_id,
                        "APPLYMENT_STATE_AUDITING",
                        "您的进件申请已提交至微信审核"
                    )

                    return {"applyment_id": applyment["id"], "wx_applyment_id": applyment_id}

                except Exception as e:
                    conn.rollback()
                    http_resp = getattr(e, "response", None)
                    status_code = getattr(http_resp, "status_code", None)

                    logger.error("提交进件申请失败: error_type=%s http_status=%s", type(e).__name__, status_code)
                    raise HTTPException(status_code=500, detail="提交进件失败，请稍后重试")

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
                logger.info("进件材料上传成功: bytes=%s", file_size)

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
                old_card_period_begin, old_card_period_end = self._extract_id_card_periods(old_subject_info)

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
                    "card_period_begin": old_card_period_begin,
                    "card_period_end": old_card_period_end,
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
                    old_card_period_begin,
                    old_card_period_end,
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
                logger.info("Core application changes submitted for review")
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

                # ✅ 修复：准备提交数据（从数据库记录构建）
                # 解析可能为JSON字符串的字段
                subject_info = applyment["subject_info"]
                if isinstance(subject_info, str):
                    subject_info = json.loads(subject_info)

                business_info = applyment.get("business_info") or {}
                if isinstance(business_info, str):
                    business_info = json.loads(business_info)

                submit_data = {
                    "business_code": applyment["business_code"],
                    "subject_type": applyment.get("subject_type", "SUBJECT_TYPE_INDIVIDUAL"),
                    "subject_info": subject_info,
                    "contact_info": applyment["contact_info"],
                    "bank_account_info": applyment["bank_account_info"],
                    "business_info": business_info
                }

                # 调用微信支付API重新提交
                response = self.pay_client.submit_applyment(submit_data, is_sub_merchant=True)
                wx_applyment_id = response.get("applyment_id")

                # ✅ 修复：更新更多字段
                update_data = {
                    "applyment_id": wx_applyment_id,  # 微信申请单号
                    "applyment_state": "APPLYMENT_STATE_AUDITING",
                    "applyment_state_msg": response.get("state_msg"),  # 新状态消息
                    "audit_detail": None,  # 清空驳回详情
                    "submitted_at": datetime.datetime.now(),  # 提交时间
                    "updated_at": datetime.datetime.now()
                }
                update_sql = build_dynamic_update(cur, "wx_applyment", update_data, "id = %s")
                params = list(update_data.values()) + [applyment_id]
                cur.execute(update_sql, tuple(params))

                # 记录日志
                self._log_state_change(cur, applyment_id, applyment["business_code"],
                                       "APPLYMENT_STATE_REJECTED", "APPLYMENT_STATE_AUDITING",
                                       "USER", "用户重新提交")

                conn.commit()
                logger.info("Application resubmitted for review")
                return {"applyment_id": applyment_id, "wx_applyment_id": wx_applyment_id}

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
        cur.execute("""
            SELECT media_type FROM wx_applyment_media 
            WHERE user_id = %s AND (applyment_id = %s OR applyment_id IS NULL OR applyment_id = 0)
        """, (user_id, applyment_id))
        uploaded = {row['media_type'] for row in cur.fetchall()}

        # ✅ 修复：根据主体类型判断所需材料
        cur.execute("SELECT subject_type FROM wx_applyment WHERE id = %s", (applyment_id,))
        subject_type = cur.fetchone()['subject_type']

        # 动态设置必需材料
        required = {'id_card_front', 'id_card_back'}
        if subject_type == 'SUBJECT_TYPE_ENTERPRISE':
            required.add('business_license')  # 企业才需要营业执照

        if not required.issubset(uploaded):
            raise HTTPException(status_code=400, detail=f"缺少必要的材料: {required - uploaded}")

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

    # services/wechat_applyment_service.py
    # 在类 WechatApplymentService 中新增辅助方法

    def _generate_card_hash(self, account_number: str, salt: str = "wx_applyment") -> str:
        """生成银行卡哈希（加盐SHA256）"""
        import hashlib
        return hashlib.sha256(f"{account_number}{salt}".encode()).hexdigest()

    def _sync_settlement_account(self, cur, applyment_id: int, user_id: int, sub_mchid: str):
        """同步进件成功的结算账户信息到 merchant_settlement_accounts 表"""
        try:
            # 获取进件资料
            cur.execute("""
                SELECT bank_account_info, subject_type 
                FROM wx_applyment 
                WHERE applyment_id = %s AND user_id = %s
            """, (applyment_id, user_id))
            result = cur.fetchone()

            if not result:
                logger.warning(f"未找到进件资料: applyment_id={applyment_id}")
                return

            bank_info = json.loads(result['bank_account_info']) if isinstance(result['bank_account_info'], str) else \
                result['bank_account_info']
            subject_type = result['subject_type']

            # 获取账户名称和账号（可能已加密）
            account_name = bank_info.get('account_name', '')
            account_number = bank_info.get('account_number', '')

            # 关键修复：正确判断是否加密（微信数据通常不会包含ENCRYPTED字样）
            # 尝试解密，如果失败则认为是明文
            try:
                # 如果数据长度较长且包含base64特征字符，则认为是加密的
                if len(account_name) > 50 and any(c in account_name for c in '+/='):
                    account_name_plain = self.pay_client._decrypt_local_encrypted(account_name)
                else:
                    account_name_plain = account_name

                if len(account_number) > 50 and any(c in account_number for c in '+/='):
                    account_number_plain = self.pay_client._decrypt_local_encrypted(account_number)
                else:
                    account_number_plain = account_number
            except Exception as e:
                logger.warning("解密结算账户信息失败: error_type=%s", type(e).__name__)
                account_name_plain = account_name
                account_number_plain = account_number

            # 关键修复：重新加密（必须使用微信支付公钥加密）
            account_name_encrypted = self.pay_client._rsa_encrypt_with_wechat_public_key(account_name_plain)
            account_number_encrypted = self.pay_client._rsa_encrypt_with_wechat_public_key(account_number_plain)

            # 生成卡号哈希（用于判重）
            card_hash = self._generate_card_hash(account_number_plain)

            # 判断账户类型
            account_type_map = {
                'SUBJECT_TYPE_INDIVIDUAL': 'BANK_ACCOUNT_TYPE_PERSONAL',
                'SUBJECT_TYPE_ENTERPRISE': 'BANK_ACCOUNT_TYPE_CORPORATE',
                'SUBJECT_TYPE_INSTITUTIONS': 'BANK_ACCOUNT_TYPE_CORPORATE',
                'SUBJECT_TYPE_OTHERS': 'BANK_ACCOUNT_TYPE_CORPORATE'
            }
            account_type = account_type_map.get(subject_type, 'BANK_ACCOUNT_TYPE_CORPORATE')

            # 构建插入数据（使用原生SQL避免参数问题）
            insert_sql = """
                INSERT INTO merchant_settlement_accounts (
                    user_id, sub_mchid, account_type, account_bank, 
                    bank_name, bank_branch_id, bank_address_code,
                    account_name_encrypted, account_number_encrypted, card_hash,
                    verify_result, status, is_default, bind_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 1, 1, NOW()
                )
                ON DUPLICATE KEY UPDATE
                    sub_mchid = VALUES(sub_mchid),
                    account_type = VALUES(account_type),
                    account_bank = VALUES(account_bank),
                    bank_name = VALUES(bank_name),
                    bank_branch_id = VALUES(bank_branch_id),
                    bank_address_code = VALUES(bank_address_code),
                    account_name_encrypted = VALUES(account_name_encrypted),
                    account_number_encrypted = VALUES(account_number_encrypted),
                    card_hash = VALUES(card_hash),
                    verify_result = VALUES(verify_result),
                    status = VALUES(status),
                    bind_at = VALUES(bind_at)
            """

            # 执行插入/更新
            cur.execute(insert_sql, (
                user_id,
                sub_mchid,
                account_type,
                bank_info.get('account_bank', ''),
                bank_info.get('bank_name', ''),
                bank_info.get('bank_branch_id', ''),
                bank_info.get('bank_address_code', ''),
                account_name_encrypted,
                account_number_encrypted,
                card_hash,
                'VERIFY_SUCCESS'  # 进件成功默认验证通过
            ))

            logger.info("同步结算账户成功")
        except Exception as e:
            logger.error("同步结算账户失败: error_type=%s", type(e).__name__)

    # 修改原有的 handle_applyment_state_change 方法
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
                    logger.error("Application record not found")
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

                # 如果审核通过，绑定商户号并同步结算账户
                if new_state == "APPLYMENT_STATE_FINISHED":
                    sub_mchid = status_info.get("sub_mchid")

                    # 1. 更新users表
                    cur.execute("""
                        UPDATE users u
                        JOIN wx_applyment wa ON u.id = wa.user_id
                        SET u.wechat_sub_mchid = %s
                        WHERE wa.applyment_id = %s
                    """, (sub_mchid, applyment_id))

                    # 2. 同步结算账户信息
                    self._sync_settlement_account(cur, applyment_id, user_id, sub_mchid)

                    # 关键修复：在推送前提交数据库事务
                    conn.commit()

                # 记录日志
                self._log_state_change(cur, applyment_id, result['business_code'],
                                       old_state, new_state, "WECHAT", status_info.get("state_msg", ""))

                # 推送通知
                await push_service.send_applyment_status_notification(
                    user_id,
                    new_state,
                    status_info.get("state_msg", "")
                )

                logger.info("Application state changed: state=%s", new_state)