import os
from collections.abc import Generator

import pymysql
import pytest
import redis

PREFIX = "test_219_"


def _required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"隔离环境未就绪：缺少环境变量 {name}")
    return value


@pytest.fixture(scope="session")
def isolated_mysql() -> Generator:
    host = _required("ISOLATED_MYSQL_HOST")
    connection = pymysql.connect(
        host=host,
        port=int(os.getenv("ISOLATED_MYSQL_PORT", "3306")),
        user=_required("ISOLATED_MYSQL_USER"),
        password=os.getenv("ISOLATED_MYSQL_PASSWORD", ""),
        database=_required("ISOLATED_MYSQL_DATABASE"),
        autocommit=False,
        connect_timeout=5,
        read_timeout=10,
        write_timeout=10,
    )
    try:
        yield connection
    finally:
        connection.close()


@pytest.fixture(scope="session")
def isolated_redis() -> Generator:
    host = _required("ISOLATED_REDIS_HOST")
    client = redis.Redis(
        host=host,
        port=int(os.getenv("ISOLATED_REDIS_PORT", "6379")),
        password=os.getenv("ISOLATED_REDIS_PASSWORD") or None,
        db=int(os.getenv("ISOLATED_REDIS_DB", "0")),
        socket_connect_timeout=5,
        socket_timeout=10,
        decode_responses=True,
    )
    client.ping()
    try:
        yield client
    finally:
        client.close()


@pytest.fixture(autouse=True)
def cleanup_synthetic_data(isolated_mysql, isolated_redis) -> Generator:
    yield
    cleanup_sql = os.getenv("ISOLATED_CLEANUP_SQL")
    if not cleanup_sql:
        raise RuntimeError(
            "隔离环境未就绪：必须配置 ISOLATED_CLEANUP_SQL，"
            "以精确删除 test_219_ 前缀合成数据"
        )
    if "test_219_" not in cleanup_sql:
        raise RuntimeError("拒绝执行未包含 test_219_ 前缀的清理 SQL")
    with isolated_mysql.cursor() as cursor:
        cursor.execute(cleanup_sql, (PREFIX,))
    isolated_mysql.commit()
    for key in isolated_redis.scan_iter(match=f"{PREFIX}*"):
        isolated_redis.delete(key)


@pytest.fixture
def seed_user(isolated_mysql):
    seed_sql = os.getenv("ISOLATED_SEED_USER_SQL")
    if not seed_sql or "test_219_" not in seed_sql:
        raise RuntimeError("请配置包含 test_219_ 的 ISOLATED_SEED_USER_SQL")
    with isolated_mysql.cursor() as cursor:
        cursor.execute(seed_sql, (PREFIX,))
        user_id = cursor.lastrowid
    isolated_mysql.commit()
    return user_id


@pytest.fixture
def seed_order(isolated_mysql):
    seed_sql = os.getenv("ISOLATED_SEED_ORDER_SQL")
    if not seed_sql or "test_219_" not in seed_sql:
        raise RuntimeError("请配置包含 test_219_ 的 ISOLATED_SEED_ORDER_SQL")
    with isolated_mysql.cursor() as cursor:
        cursor.execute(seed_sql, (PREFIX,))
        order_id = cursor.lastrowid
    isolated_mysql.commit()
    return order_id
