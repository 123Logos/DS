#!/usr/bin/env python3
import os
import time
import json
import base64
import uuid
import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# 配置（推荐使用环境变量）
PRIVATE_KEY_PATH = os.environ.get('PRIVATE_KEY_PATH', 'certs/apiclient_key.pem')
MERCHANT_SERIAL = os.environ.get('MERCHANT_SERIAL', 'TEST_SERIAL')
NOTIFY_URL = os.environ.get('NOTIFY_URL', 'http://127.0.0.1:5231/wechat-pay/notify')
PORT = int(os.environ.get('PORT', 5000))

app = FastAPI()


def load_private_key(path: str):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def sign_message(private_key, message: bytes) -> str:
    sig = private_key.sign(
        message,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode()


@app.post('/dev/trigger_notify')
async def trigger_notify(req: Request):
    data = await req.json()
    out_trade_no = data.get('out_trade_no', f'TEST{int(time.time())}')
    amount = int(data.get('amount', 100))
    event_type = data.get('event_type', 'TRANSACTION.SUCCESS')
    bypass = bool(data.get('bypass_signature', False))

    body = {
        "resource": {
            "event_type": event_type,
            "out_trade_no": out_trade_no,
            "transaction_id": f"WX{int(time.time())}",
            "amount": {"total": amount}
        }
    }
    body_json = json.dumps(body, separators=(',', ':'))

    headers = {'Content-Type': 'application/json'}

    if not bypass:
        timestamp = str(int(time.time()))
        nonce = uuid.uuid4().hex
        message = f"{timestamp}\n{nonce}\n{body_json}\n".encode('utf-8')
        try:
            private_key = load_private_key(PRIVATE_KEY_PATH)
            signature = sign_message(private_key, message)
            headers.update({
                'Wechatpay-Signature': signature,
                'Wechatpay-Timestamp': timestamp,
                'Wechatpay-Nonce': nonce,
                'Wechatpay-Serial': MERCHANT_SERIAL
            })
        except Exception as e:
            return JSONResponse(status_code=500, content={'error': f'load/sign private key failed: {e}'})

    try:
        resp = requests.post(NOTIFY_URL, data=body_json.encode('utf-8'), headers=headers, timeout=10, verify=False)
        return JSONResponse(status_code=200, content={
            'status_code': resp.status_code,
            'resp_text': resp.text
        })
    except Exception as e:
        return JSONResponse(status_code=500, content={'error': str(e)})


if __name__ == '__main__':
    uvicorn.run(app, host='0.0.0.0', port=PORT)
