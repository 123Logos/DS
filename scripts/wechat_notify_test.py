#!/usr/bin/env python3
"""
本脚本用于在受控服务器上模拟微信回调：
- 使用本地商户私钥对回调明文签名（RSA-SHA256 + base64）
- 发送到 /wechat-pay/notify

注意：仅在受控开发/测试环境中运行。私钥路径请使用受限权限文件。
"""
import os
import sys
import json
import time
import base64
import argparse
import requests
import secrets
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 默认配置（可通过命令行覆盖）
DEFAULT_URL = os.getenv('WX_NOTIFY_URL', 'https://hzai.tech/wechat-pay/notify')
DEFAULT_KEY_PATH = os.getenv('WECHAT_MERCHANT_KEY_PATH', '/var/www/DS/certs/apiclient_key.pem')


def load_private_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sign_callback(private_key, timestamp: str, nonce: str, body: str) -> str:
    message = f"{timestamp}\n{nonce}\n{body}\n"
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')


def build_body(event_type='TRANSACTION.SUCCESS', out_trade_no='TEST123', tx_id='WX123', amount=100, as_json=True):
    if as_json:
        return json.dumps({
            "resource": {
                "event_type": event_type,
                "out_trade_no": out_trade_no,
                "transaction_id": tx_id,
                "amount": {"total": amount}
            }
        }, ensure_ascii=False)
    else:
        # xml wrapper where <resource> contains JSON string (matches routes.py handling)
        resource = json.dumps({
            "event_type": event_type,
            "out_trade_no": out_trade_no,
            "transaction_id": tx_id,
            "amount": {"total": amount}
        }, ensure_ascii=False)
        return '<?xml version="1.0" encoding="utf-8"?><xml><resource>' + resource + '</resource></xml>'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--url', default=DEFAULT_URL)
    parser.add_argument('--key', default=DEFAULT_KEY_PATH)
    parser.add_argument('--xml', action='store_true', help='Use XML wrapper')
    parser.add_argument('--bypass', action='store_true', help='Add X-Bypass-Signature header to skip verification on server (dev only)')
    parser.add_argument('--out_trade_no', default='TEST123')
    parser.add_argument('--amount', type=int, default=100)
    args = parser.parse_args()

    url = args.url
    key_path = args.key

    if not Path(key_path).exists():
        print(f"私钥文件不存在: {key_path}")
        sys.exit(2)

    private_key = load_private_key(key_path)

    as_json = not args.xml
    body = build_body(out_trade_no=args.out_trade_no, amount=args.amount, as_json=as_json)
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)

    signature = sign_callback(private_key, timestamp, nonce, body)

    headers = {
        'Content-Type': 'application/json' if as_json else 'application/xml',
        'Wechatpay-Signature': signature,
        'Wechatpay-Timestamp': timestamp,
        'Wechatpay-Nonce': nonce,
        'Wechatpay-Serial': 'TEST_SERIAL'
    }

    if args.bypass:
        headers['X-Bypass-Signature'] = 'true'

    print('发送到:', url)
    print('Headers:', {k: headers[k] for k in headers if k != 'Wechatpay-Signature'})
    print('Body:', body[:200])

    try:
        r = requests.post(url, data=body.encode('utf-8'), headers=headers, timeout=15)
        print('响应状态:', r.status_code)
        print('响应体:', r.text)
    except Exception as e:
        print('请求失败:', e)


if __name__ == '__main__':
    main()
