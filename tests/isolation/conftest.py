import json
import os
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import threading

import pymysql
import pytest
import redis

from scripts.security_isolation.safety import guard, block_external_network

# Applied before importing the real application, including all provider clients.
RUN_ID = guard()
block_external_network()


@pytest.fixture(scope='session')
def db():
    @contextmanager
    def connect():
        from core.config import get_db_config
        conn = pymysql.connect(**get_db_config(), cursorclass=pymysql.cursors.DictCursor)
        try:
            yield conn
        finally:
            conn.rollback()
            conn.close()
    return connect


@pytest.fixture(scope='session')
def isolated_redis():
    client = redis.Redis(host=os.environ['REDIS_HOST'], port=int(os.environ['REDIS_PORT']),
        password=os.environ.get('REDIS_PASSWORD') or None, db=15, decode_responses=True)
    assert client.get('__security_isolation_owner__') == RUN_ID
    yield client
    client.close()


@pytest.fixture(scope='session')
def http():
    from fastapi.testclient import TestClient
    from main import app
    with TestClient(app, raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def race():
    def run(*actions):
        barrier = threading.Barrier(len(actions))
        def invoke(action):
            barrier.wait(timeout=15)
            return action()
        with ThreadPoolExecutor(max_workers=len(actions)) as pool:
            futures = [pool.submit(invoke, action) for action in actions]
            return [future.result(timeout=30) for future in futures]
    return run


@pytest.fixture
def evidence(request):
    events = []
    yield events.append
    path = Path(os.environ['SECURITY_ISOLATION_RESOURCE_DIR']) / 'evidence.jsonl'
    with path.open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'test': request.node.nodeid, 'events': events}, default=str) + '\n')


def snapshot(conn):
    with conn.cursor() as cur:
        cur.execute('SHOW TABLES')
        tables = [next(iter(row.values())) for row in cur.fetchall()]
        result = {}
        for table in tables:
            cur.execute(f'SELECT * FROM `{table}`')
            # Synthetic isolated DB only; excludes authentication secrets from artifacts.
            rows = cur.fetchall()
            result[table] = {'rows': len(rows)}
            sums = {}
            for row in rows:
                for key, value in row.items():
                    if any(term in key for term in ('balance', 'points', 'stock', 'amount', 'fee')) and isinstance(value, (int, float)):
                        sums[key] = sums.get(key, 0) + value
                    elif any(term in key for term in ('balance', 'points', 'stock', 'amount', 'fee')) and type(value).__name__ == 'Decimal':
                        sums[key] = sums.get(key, 0) + value
            result[table]['sums'] = sums
        return result


@pytest.fixture(autouse=True)
def record_invariants(db, evidence):
    with db() as conn:
        evidence({'before': snapshot(conn)})
    yield
    with db() as conn:
        evidence({'after': snapshot(conn)})


@pytest.fixture
def users(db):
    import bcrypt
    password = 'Synthetic-pass-42!'
    with db() as conn:
        with conn.cursor() as cur:
            ids = []
            for index in range(4):
                cur.execute('INSERT INTO users(name,mobile,password_hash,is_merchant,status) VALUES(%s,%s,%s,%s,0)',
                    (RUN_ID + '_' + str(index), '199' + str(int.from_bytes(os.urandom(4), 'big') % 100000000).zfill(8),
                     bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(), int(index == 2)))
                ids.append(cur.lastrowid)
        conn.commit()
    return ids


@pytest.fixture
def token():
    from core.auth import create_access_token
    return create_access_token
