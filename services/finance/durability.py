"""Durable identities participate in the caller's InnoDB transaction."""
import hashlib
import json

from fastapi import HTTPException


def fingerprint(payload):
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':'), default=str).encode()).hexdigest()


def begin_request(cur, actor_id, request_key, operation, payload):
    digest = fingerprint(payload)
    cur.execute(
        "INSERT INTO finance_requests(actor_id,request_key,operation,payload_hash) VALUES(%s,%s,%s,%s) "
        "ON DUPLICATE KEY UPDATE actor_id=actor_id",
        (actor_id, request_key, operation, digest),
    )
    cur.execute("SELECT operation,payload_hash,result_json FROM finance_requests WHERE actor_id=%s AND request_key=%s FOR UPDATE", (actor_id, request_key))
    row = cur.fetchone()
    if row['operation'] != operation or row['payload_hash'] != digest:
        raise HTTPException(409, 'Idempotency-Key 已用于不同请求')
    result = row['result_json']
    return json.loads(result) if isinstance(result, str) else result


def finish_request(cur, actor_id, request_key, result):
    cur.execute("UPDATE finance_requests SET result_json=%s WHERE actor_id=%s AND request_key=%s", (json.dumps(result), actor_id, request_key))


def begin_event(cur, kind, key, order_number, payload):
    digest = fingerprint(payload)
    cur.execute(
        "INSERT INTO finance_events(event_kind,event_key,order_number,payload_hash) VALUES(%s,%s,%s,%s) "
        "ON DUPLICATE KEY UPDATE event_key=event_key", (kind, key, order_number, digest),
    )
    cur.execute("SELECT order_number,payload_hash,result_json FROM finance_events WHERE event_kind=%s AND event_key=%s FOR UPDATE", (kind, key))
    row = cur.fetchone()
    if row['order_number'] != order_number or row['payload_hash'] != digest:
        raise ValueError('Financial event identity conflict')
    return row['result_json'] is not None


def finish_event(cur, kind, key):
    cur.execute("UPDATE finance_events SET result_json='true' WHERE event_kind=%s AND event_key=%s", (kind, key))
