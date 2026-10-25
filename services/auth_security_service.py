"""Tencent Cloud SMS boundary and MySQL-backed single-use challenges."""
import hashlib
import hmac
import json
import secrets
import time
from datetime import datetime, timezone

import requests
from fastapi import HTTPException
from core.config import settings
from core.database import get_conn


def _secret():
    value = settings.SMS_CODE_SECRET.get_secret_value()
    if len(value) < 32:
        raise HTTPException(503, "短信服务暂不可用")
    return value.encode()


def digest(value):
    return hmac.new(_secret(), value.encode(), hashlib.sha256).hexdigest()


def audit(cur, operator_id, target_id, action, before, after, reason):
    cur.execute("""INSERT INTO security_operator_audit
        (operator_id,target_id,action,before_json,after_json,reason) VALUES(%s,%s,%s,%s,%s,%s)""",
        (operator_id, target_id, action, json.dumps(before, default=str), json.dumps(after, default=str), reason[:200]))


def revoke_user_sessions(cur, user_id):
    cur.execute("DELETE FROM sessions WHERE user_id=%s", (user_id,))


def send_sms(mobile, code, purpose, request_id):
    """SendSms API 2021-01-11; acceptance is not delivery. Never retry unknown sends."""
    template = settings.SMS_RESET_TEMPLATE_ID if purpose == "password_reset" else settings.SMS_BANKCARD_TEMPLATE_ID
    if not all((settings.SMS_SDK_APP_ID, settings.SMS_SIGN_NAME, template)):
        raise HTTPException(503, "短信服务暂不可用")
    result = _sms_request("SendSms", {"PhoneNumberSet": ["+86" + mobile], "SmsSdkAppId": settings.SMS_SDK_APP_ID,
        "SignName": settings.SMS_SIGN_NAME, "TemplateId": template, "TemplateParamSet": [code],
        "SessionContext": request_id})
    statuses = result.get("SendStatusSet", [])
    if result.get("Error") or len(statuses) != 1 or statuses[0].get("Code") != "Ok":
        raise HTTPException(503, "短信供应商拒绝请求")
    return statuses[0]["SerialNo"]


def _sms_request(action, payload):
    secret = settings.SMS_SECRET_KEY.get_secret_value()
    if not settings.SMS_SECRET_ID or not secret:
        raise HTTPException(503, "短信服务暂不可用")
    body = json.dumps(payload, separators=(",", ":"))
    timestamp = int(time.time())
    date = datetime.fromtimestamp(timestamp, timezone.utc).strftime("%Y-%m-%d")
    canonical = "POST\n/\n\ncontent-type:application/json; charset=utf-8\nhost:sms.tencentcloudapi.com\n\ncontent-type;host\n" + hashlib.sha256(body.encode()).hexdigest()
    scope = date + "/sms/tc3_request"
    to_sign = "TC3-HMAC-SHA256\n" + str(timestamp) + "\n" + scope + "\n" + hashlib.sha256(canonical.encode()).hexdigest()
    def sign(key, value):
        return hmac.new(key, value.encode(), hashlib.sha256).digest()
    key = sign(sign(sign(("TC3" + secret).encode(), date), "sms"), "tc3_request")
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    response = requests.post("https://sms.tencentcloudapi.com/", data=body.encode(), timeout=settings.SMS_TIMEOUT_SECONDS,
        headers={"Content-Type": "application/json; charset=utf-8", "X-TC-Action": action,
        "X-TC-Version": "2021-01-11", "X-TC-Timestamp": str(timestamp), "X-TC-Region": settings.SMS_REGION,
        "Authorization": f"TC3-HMAC-SHA256 Credential={settings.SMS_SECRET_ID}/{scope}, SignedHeaders=content-type;host, Signature={signature}"})
    response.raise_for_status()
    result = response.json()["Response"]
    if result.get("Error"):
        raise HTTPException(503, "短信供应商请求失败")
    return result


def reconcile_sms_receipts(mobile, begin_time, end_time):
    """Operator-only Python entry point; no blind resend on uncertain acceptance."""
    result = _sms_request("PullSmsSendStatusByPhoneNumber", {
        "SmsSdkAppId": settings.SMS_SDK_APP_ID, "PhoneNumber": "+86"+mobile,
        "BeginTime": int(begin_time), "EndTime": int(end_time), "Offset": 0, "Limit": 100})
    receipts = result.get("PullSmsSendStatusSet", [])
    with get_conn() as conn:
        with conn.cursor() as cur:
            for receipt in receipts:
                serial = receipt.get("SerialNo")
                if serial:
                    cur.execute("UPDATE auth_sms_challenges SET delivery_status=%s WHERE mobile=%s AND provider_message_id=%s",
                        ("delivered" if receipt.get("ReportStatus") == "SUCCESS" else "failed", mobile, serial))
            conn.commit()
    return {"receipts_processed": len(receipts)}


def _limit(cur, scope, maximum, issuance=False):
    key = digest(scope)
    cur.execute("INSERT IGNORE INTO auth_sms_limits(scope_hash,window_start) VALUES(%s,NOW())", (key,))
    cur.execute("SELECT *,window_start<=DATE_SUB(NOW(),INTERVAL 1 HOUR) AS stale, last_issued_at>DATE_SUB(NOW(),INTERVAL 60 SECOND) AS cooling FROM auth_sms_limits WHERE scope_hash=%s FOR UPDATE", (key,))
    row = cur.fetchone()
    if row["stale"]:
        cur.execute("UPDATE auth_sms_limits SET window_start=NOW(),issuance_count=0,attempt_count=0 WHERE scope_hash=%s", (key,))
        row["issuance_count"] = row["attempt_count"] = 0
    field = "issuance_count" if issuance else "attempt_count"
    if row[field] >= maximum or (issuance and scope.startswith("mobile:") and row["cooling"]):
        return False
    cur.execute(f"UPDATE auth_sms_limits SET {field}={field}+1" + (",last_issued_at=NOW()" if issuance else "") + " WHERE scope_hash=%s", (key,))
    return True


def issue_sms(mobile, purpose, subject, ip, device, user_id=None):
    if purpose not in {"password_reset", "bankcard_bind", "bankcard_modify"}:
        raise ValueError("Unsupported SMS purpose")
    session = secrets.token_hex(16)
    code = f"{secrets.randbelow(1000000):06d}"
    subject_hash = digest(subject)
    with get_conn() as conn:
        with conn.cursor() as cur:
            if purpose == "password_reset":
                cur.execute("SELECT id FROM users WHERE mobile=%s FOR UPDATE", (mobile,))
                target = cur.fetchone()
                user_id = target["id"] if target else None
            permitted = True
            for scope, maximum in sorted((("mobile:"+mobile, 5), ("ip:"+ip, 20), ("device:"+device, 10), ("global", settings.SMS_GLOBAL_HOURLY_LIMIT))):
                if not _limit(cur, scope, maximum, True):
                    permitted = False
            if not permitted:
                conn.commit()
                raise HTTPException(429, "短信请求过于频繁")
            cur.execute("""INSERT INTO auth_sms_challenges(session_id,mobile,purpose,subject_hash,code_hash,user_id,send_status,expires_at)
                VALUES(%s,%s,%s,%s,%s,%s,'pending',DATE_ADD(NOW(),INTERVAL 5 MINUTE))""",
                (session,mobile,purpose,subject_hash,digest(session+":"+code),user_id))
            conn.commit()
    try:
        message_id = send_sms(mobile, code, purpose, session)
        status = "accepted"
    except Exception as exc:
        failure = "rejected" if isinstance(exc, HTTPException) else "unknown"
        with get_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE auth_sms_challenges SET send_status=%s WHERE session_id=%s", (failure,session))
                conn.commit()
        raise HTTPException(503, "短信未确认受理，请稍后重新申请")
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE auth_sms_challenges SET send_status=%s,provider_message_id=%s WHERE session_id=%s", (status,message_id,session))
            conn.commit()
    return {"session_id": session, "expired_in": 300, "retry_after": 60, "status": "accepted"}


def consume_sms(cur, mobile, purpose, subject, code, session_id=None, expected_user_id=None):
    # Caller commits rejected attempts; successful consumption shares the business transaction.
    if not _limit(cur, "attempt:"+mobile+":"+purpose, 5):
        return False
    cur.execute("""SELECT *,expires_at>NOW() AS alive FROM auth_sms_challenges
        WHERE mobile=%s AND purpose=%s AND subject_hash=%s ORDER BY id DESC LIMIT 1 FOR UPDATE""",
        (mobile,purpose,digest(subject)))
    row = cur.fetchone()
    if not row or not row["alive"] or row["consumed_at"] or row["send_status"] != "accepted":
        return False
    if purpose == "password_reset" and (expected_user_id is None or row["user_id"] != expected_user_id):
        return False
    if session_id is not None and session_id != row["session_id"]:
        return False
    if not hmac.compare_digest(row["code_hash"], digest(row["session_id"]+":"+code)):
        return False
    cur.execute("UPDATE auth_sms_challenges SET consumed_at=NOW() WHERE id=%s AND consumed_at IS NULL", (row["id"],))
    return cur.rowcount == 1
