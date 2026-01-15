#!/usr/bin/env python3
"""
scripts/send_notify.py

签名并发送模拟微信回调（用于开发/测试）。
支持两种模式：
 - 使用商户私钥生成真实 RSA-SHA256 签名（提供 --key）
 - 使用伪造签名并通过开发头绕过（--bypass）

用法示例:
  uv run scripts/send_notify.py --url http://127.0.0.1:5231/wechat-pay/notify --key ./certs/apiclient_key.pem
  uv run scripts/send_notify.py --url http://127.0.0.1:5231/wechat-pay/notify --bypass --plain

注意：私钥文件只能放在受控后端环境，切勿上传到前端。
"""
import argparse
import json
import time
import uuid
import base64
import sys
import os
from pathlib import Path

import requests

# Ensure project root on sys.path so core.config can be imported when run via `uv run`
project_root = Path(__file__).resolve().parents[1]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from core.config import ENVIRONMENT, WECHAT_PAY_API_V3_KEY, WX_APIV3_KEY
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except Exception:
    # cryptography may not be available in some minimal test environments
    hashes = serialization = padding = None


def load_private_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def build_signature(private_key, timestamp: str, nonce: str, body: str) -> str:
    message = f"{timestamp}\n{nonce}\n{body}\n".encode('utf-8')
    signature = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode('utf-8')


def make_body(event_type="TRANSACTION.SUCCESS", out_trade_no="TEST123456"):
    return {
        "resource": {
            "event_type": event_type,
            "out_trade_no": out_trade_no,
            "transaction_id": f"WX_{int(time.time())}",
            "amount": {"total": 100},
        }
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:5231/wechat-pay/notify", help="回调地址")
    parser.add_argument("--key", default=None, help="商户私钥 PEM 文件路径（可选，用于真实签名）")
    parser.add_argument("--bypass", action="store_true", help="在开发环境绕过签名校验（发送 X-DEV-BYPASS-VERIFY）")
    parser.add_argument("--plain", action="store_true", help="表示 resource 为明文（发送 X-DEV-PLAIN-BODY）")
    parser.add_argument("--test-token", default=None, help="发送 X-DEV-TEST-TOKEN 用于受控绕过")
    parser.add_argument("--event", default="TRANSACTION.SUCCESS")
    parser.add_argument("--out", default="TEST123456")
    parser.add_argument("--encrypt", action="store_true", help="使用 WECHAT_PAY_API_V3_KEY 加密 resource（用于测试 decrypt_callback_data）")
    args = parser.parse_args()

    body = make_body(event_type=args.event, out_trade_no=args.out)
    body_str = json.dumps(body, ensure_ascii=False)

    # 支持 AES-256-GCM 加密 resource（模拟微信回调的 resource 格式）
    if args.encrypt:
        key = (WECHAT_PAY_API_V3_KEY or WX_APIV3_KEY or '').encode('utf-8')
        if not key or len(key) < 16:
            print('未配置 WECHAT_PAY_API_V3_KEY 或长度不够，无法加密')
            sys.exit(2)
        # 保证 key 为 32 字节
        key = key[:32].ljust(32, b'0')
        aesgcm = AESGCM(key)

        # 按微信规范：只对 resource 对象本身进行加密，解密后应得到 resource 的明文 JSON
        clear_resource = body.get('resource', {})
        clear_resource_str = json.dumps(clear_resource, ensure_ascii=False)

        # 生成 12 字节随机 nonce（原始字节），使用 base64 编码传输
        nonce_bytes = os.urandom(12)
        associated_data = b''
        cipher = aesgcm.encrypt(nonce_bytes, clear_resource_str.encode('utf-8'), associated_data)
        ciphertext_b64 = base64.b64encode(cipher).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce_bytes).decode('utf-8')
        resource = {
            'ciphertext': ciphertext_b64,
            'nonce': nonce_b64,
            'associated_data': ''
        }
        payload = {'resource': resource}
        # Use ASCII-safe JSON to avoid any encoding ambiguity when posting
        body_str = json.dumps(payload, ensure_ascii=True)

    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex

    headers = {
        "Content-Type": "application/json",
        "Wechatpay-Timestamp": ts,
        "Wechatpay-Nonce": nonce,
        "Wechatpay-Serial": "TEST_SERIAL",
    }

    # 生成签名或使用伪造签名
    if args.key:
        if serialization is None:
            print("cryptography 未安装，无法使用私钥签名")
            sys.exit(2)
        private_key = load_private_key(args.key)
        headers["Wechatpay-Signature"] = build_signature(private_key, ts, nonce, body_str)
    else:
        headers["Wechatpay-Signature"] = "MOCK_SIGNATURE_BASE64"

    if args.bypass:
        headers["X-DEV-BYPASS-VERIFY"] = "1"
    if args.plain:
        headers["X-DEV-PLAIN-BODY"] = "1"
    if args.test_token:
        headers["X-DEV-TEST-TOKEN"] = args.test_token

    print("POST", args.url)
    print("Headers:", {k: headers[k] for k in ["Wechatpay-Timestamp", "Wechatpay-Nonce", "Wechatpay-Signature"]})
    if args.bypass:
        print("Dev bypass header included")

    try:
        if ENVIRONMENT == 'production' and (args.bypass or args.plain):
            print("警告：当前 ENVIRONMENT=production，禁止使用绕过选项。取消绕过。")
            headers.pop("X-DEV-BYPASS-VERIFY", None)
            headers.pop("X-DEV-PLAIN-BODY", None)
        # (removed detailed debug body print)

        resp = requests.post(args.url, data=body_str.encode('utf-8'), headers=headers, timeout=10, verify=False)
        print("Response:", resp.status_code)
        print(resp.text)
    except Exception as e:
        print("请求异常:", e)
        sys.exit(2)


if __name__ == '__main__':
    main()
