"""V1.1 权益服务的 MySQL 集成测试（并发超发、Q4 转券、Q7 不扣底池、Q12 暂缓、幂等）。

测试使用独立的临时数据库（名字随机，结束后 DROP），不触碰 .env 配置的业务库。
MySQL 不可用时整组自动 skip，不会让 CI 变红。
"""
from __future__ import annotations

import contextlib
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import date
from decimal import Decimal
from pathlib import Path

import pymysql
import pytest

from services import rights_service, settlement_service
from services.rights_service import RightsError, RightsService
from services.settlement_service import SubsidyPayoutDisabled, SettlementService

ROOT = Path(__file__).resolve().parent.parent
MIGRATION = ROOT / "migrations" / "007_v1_rights.sql"
INITIAL_POOL = Decimal("1000000")
TOTAL_SUPPLY = Decimal("100000000")


def _mysql_kwargs(database: str | None = None) -> dict:
    from core.config import get_db_config

    cfg = get_db_config()
    kwargs = {
        "host": cfg["host"],
        "port": cfg["port"],
        "user": cfg["user"],
        "password": cfg["password"],
        "charset": "utf8mb4",
        "cursorclass": pymysql.cursors.DictCursor,
    }
    if database:
        kwargs["database"] = database
    return kwargs


def _migration_statements() -> list[str]:
    sql = MIGRATION.read_text(encoding="utf-8")
    return [stmt.strip() for stmt in sql.split(";") if stmt.strip()]


class ScratchDatabase:
    """临时库句柄：提供与 core.database.get_conn 同语义的连接上下文。"""

    def __init__(self, name: str):
        self.name = name

    @contextlib.contextmanager
    def connect(self):
        conn = pymysql.connect(**_mysql_kwargs(self.name))
        try:
            yield conn
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def exec(self, sql: str, params: tuple = ()):
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
            conn.commit()

    def one(self, sql: str, params: tuple = ()):
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchone()

    def all(self, sql: str, params: tuple = ()) -> list:
        with self.connect() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                return cur.fetchall() or []

    def reset(self):
        with self.connect() as conn:
            with conn.cursor() as cur:
                for table in (
                    "rights_ledger",
                    "rights_operations",
                    "rights_daily_settlements",
                    "rights_coupon_batches",
                    "wine_listings",
                    "wine_jars",
                    "user_assets",
                    "users",
                    "finance_accounts",
                    "system_pools",
                ):
                    cur.execute(f"TRUNCATE TABLE {table}")
                cur.execute(
                    """INSERT INTO system_pools
                           (id, total_egg_supply, pool_coupon_balance, subsidy_coupon_balance,
                            platform_egg_balance, valuation_version)
                       VALUES (1, %s, %s, 0, %s, 1)""",
                    (TOTAL_SUPPLY, INITIAL_POOL, TOTAL_SUPPLY),
                )
            conn.commit()


@pytest.fixture(scope="module")
def scratch_db():
    try:
        admin = pymysql.connect(**_mysql_kwargs())
    except Exception as exc:  # pragma: no cover - 环境相关
        pytest.skip(f"MySQL 不可用，跳过 V1.1 集成测试: {exc}")

    name = f"ds_v1_rights_{uuid.uuid4().hex[:10]}"
    with admin.cursor() as cur:
        cur.execute(f"CREATE DATABASE `{name}` DEFAULT CHARACTER SET utf8mb4")
    admin.close()

    conn = pymysql.connect(**_mysql_kwargs(name))
    try:
        with conn.cursor() as cur:
            cur.execute(
                """CREATE TABLE users (
                       id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
                       member_level TINYINT NOT NULL DEFAULT 0,
                       member_points DECIMAL(12,6) NOT NULL DEFAULT 0
                   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
            )
            cur.execute(
                """CREATE TABLE finance_accounts (
                       id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                       account_type VARCHAR(50) NOT NULL,
                       balance DECIMAL(14,4) NOT NULL DEFAULT 0,
                       config_params JSON NULL
                   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"""
            )
            for stmt in _migration_statements():
                cur.execute(stmt)
        conn.commit()
    finally:
        conn.close()

    db = ScratchDatabase(name)
    yield db

    admin = pymysql.connect(**_mysql_kwargs())
    with admin.cursor() as cur:
        cur.execute(f"DROP DATABASE IF EXISTS `{name}`")
    admin.close()


@pytest.fixture
def store(scratch_db, monkeypatch):
    scratch_db.reset()
    monkeypatch.setattr(rights_service, "get_conn", scratch_db.connect)
    monkeypatch.setattr(settlement_service, "get_conn", scratch_db.connect)
    return scratch_db


def _race(times: int, action):
    """所有线程在同一起跑线并发执行，返回结果或异常对象。"""
    barrier = threading.Barrier(times)

    def invoke():
        barrier.wait(timeout=15)
        try:
            return action()
        except Exception as exc:  # noqa: BLE001 - 并发测试需要捕获业务异常做断言
            return exc

    with ThreadPoolExecutor(max_workers=times) as pool:
        futures = [pool.submit(invoke) for _ in range(times)]
        return [future.result(timeout=60) for future in futures]


# ==================== 并发兑换防超发 ====================

def test_concurrent_exchange_is_atomic_and_never_oversells(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, coupon_balance) VALUES (1, 1000)")

    results = _race(8, lambda: RightsService().exchange_eggs(1, "100"))
    successes = [r for r in results if isinstance(r, dict)]
    failures = [r for r in results if isinstance(r, Exception)]

    assert not failures, f"并发兑换不应失败: {failures}"
    assert len(successes) == 8

    pools = store.one("SELECT * FROM system_pools WHERE id = 1")
    assets = store.one("SELECT * FROM user_assets WHERE user_id = 1")
    total_eggs = sum(Decimal(r["egg_quantity"]) for r in successes)

    # 1000 券中兑出 800，剩余 200，券账必须精确闭合
    assert Decimal(assets["coupon_balance"]) == Decimal("200.000000")
    # 80% 入底池、20% 入补贴池，合计等于提交量
    assert Decimal(pools["pool_coupon_balance"]) == INITIAL_POOL + Decimal("640.000000")
    assert Decimal(pools["subsidy_coupon_balance"]) == Decimal("160.000000")
    # 平台蛋库存减少量 = 会员获得的蛋数量（无超发、无凭空生成）
    assert Decimal(assets["egg_quantity"]) == total_eggs
    assert Decimal(pools["platform_egg_balance"]) == TOTAL_SUPPLY - total_eggs
    assert Decimal(pools["platform_egg_balance"]) >= 0

    # 每次兑换恰好两条流水，且流水余额与最终资产一致
    ledger = store.all("SELECT asset_type, SUM(quantity_delta) AS delta FROM rights_ledger GROUP BY asset_type")
    deltas = {row["asset_type"]: Decimal(row["delta"]) for row in ledger}
    assert deltas["coupon"] == Decimal("-800.000000")
    assert deltas["egg"] == total_eggs


def test_concurrent_exchange_respects_platform_inventory(store):
    """平台库存不足时，并发操作必须整笔失败，不得部分成交或出现负库存。"""
    store.exec("UPDATE system_pools SET pool_coupon_balance = 100, platform_egg_balance = 10000 WHERE id = 1")
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, coupon_balance) VALUES (1, 10000)")

    # 价格 0.01 时 1000 券需 80,000 枚，远超 10,000 枚库存
    results = _race(8, lambda: RightsService().exchange_eggs(1, "1000"))
    failures = [r for r in results if isinstance(r, Exception)]

    assert len(failures) == 8, "库存不足时必须全部拒绝"
    assert all(isinstance(f, RightsError) and f.code == "POOL_INSUFFICIENT" for f in failures)

    pools = store.one("SELECT * FROM system_pools WHERE id = 1")
    assets = store.one("SELECT * FROM user_assets WHERE user_id = 1")
    assert Decimal(pools["platform_egg_balance"]) == Decimal("10000")
    assert Decimal(pools["pool_coupon_balance"]) == Decimal("100")
    assert Decimal(assets["coupon_balance"]) == Decimal("10000.000000")
    assert Decimal(assets["egg_quantity"]) == Decimal("0")
    assert store.all("SELECT id FROM rights_ledger") == []


def test_concurrent_exchange_conserves_egg_supply(store):
    """库存被并发逐步耗尽时，蛋守恒：平台剩余 + 会员持有 = 初始库存。"""
    store.exec("UPDATE system_pools SET pool_coupon_balance = 100, platform_egg_balance = 20000 WHERE id = 1")
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, coupon_balance) VALUES (1, 10000)")

    results = _race(8, lambda: RightsService().exchange_eggs(1, "100"))
    successes = [r for r in results if isinstance(r, dict)]
    assert successes

    pools = store.one("SELECT * FROM system_pools WHERE id = 1")
    assets = store.one("SELECT * FROM user_assets WHERE user_id = 1")
    assert Decimal(pools["platform_egg_balance"]) >= 0
    assert Decimal(pools["platform_egg_balance"]) + Decimal(assets["egg_quantity"]) == Decimal("20000")
    assert Decimal(assets["coupon_balance"]) == Decimal(10000) - Decimal(100) * len(successes)
    assert Decimal(pools["pool_coupon_balance"]) == Decimal(100) + Decimal(80) * len(successes)


# ==================== 兑换预报价（不扣券） ====================

def test_quote_egg_exchange_preview(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, coupon_balance) VALUES (1, 100)")

    quote = RightsService().quote_egg_exchange(1, "100")
    assert quote["pool_in_quantity"] == "80.000000"
    assert quote["subsidy_in_quantity"] == "20.000000"
    assert quote["egg_quantity"] == "8000.000000"
    assert quote["unit_value"] == "0.010000"
    # 报价只读，不产生任何资产变动
    assert Decimal(store.one("SELECT coupon_balance FROM user_assets WHERE user_id = 1")["coupon_balance"]) == Decimal("100")
    assert store.all("SELECT id FROM rights_ledger") == []


# ==================== Q4 加权平均 + Q5 转券扣底池 ====================

def test_weighted_average_cost_and_auto_conversion_in_db(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, coupon_balance) VALUES (1, 1000)")
    service = RightsService()

    first = service.exchange_eggs(1, "100")
    assert first["egg_quantity"] == "8000.000000"
    assert first["executed_unit_value"] == "0.010000"
    assert first["avg_cost_goda_value"] == "0.010000"

    # 模拟其他会员兑换推高底池：让咯哒值精确等于 0.02（平台剩余 + 会员持有 = 1 亿）
    store.exec("UPDATE system_pools SET pool_coupon_balance = 1999840, platform_egg_balance = 99992000 WHERE id = 1")
    second = service.exchange_eggs(1, "100")
    assert second["executed_unit_value"] == "0.020000"
    assert second["egg_quantity"] == "4000.000000"
    # (8000×0.01 + 4000×0.02) / 12000 = 0.013333...
    assert second["avg_cost_goda_value"] == "0.013333"
    assert "auto_conversion" not in second

    # 咯哒值继续升至 0.03，超过成本 0.013333×2，触发自动转券
    store.exec("UPDATE system_pools SET pool_coupon_balance = 2999640 WHERE id = 1")
    conversion = service.maybe_auto_convert(1)
    assert conversion is not None
    assert conversion["egg_quantity_converted"] == "12000.000000"
    assert conversion["goda_coupon_quantity"] == "360.000000"

    assets = store.one("SELECT * FROM user_assets WHERE user_id = 1")
    pools = store.one("SELECT * FROM system_pools WHERE id = 1")
    assert Decimal(assets["egg_quantity"]) == Decimal("0")
    assert Decimal(assets["avg_cost_goda_value"]) == Decimal("0")
    assert Decimal(assets["goda_coupon_balance"]) == Decimal("360.000000")
    # Q5：转券扣底池、清零的蛋回补平台库存
    assert Decimal(pools["pool_coupon_balance"]) == Decimal("2999640") - Decimal("360")
    assert Decimal(pools["platform_egg_balance"]) == TOTAL_SUPPLY

    # 幂等：再次监测不会重复转券
    assert service.maybe_auto_convert(1) is None


def test_auto_conversion_not_triggered_below_double(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, coupon_balance) VALUES (1, 1000)")
    service = RightsService()
    service.exchange_eggs(1, "100")
    store.exec("UPDATE system_pools SET pool_coupon_balance = 1980000 WHERE id = 1")
    assert service.maybe_auto_convert(1) is None
    assets = store.one("SELECT * FROM user_assets WHERE user_id = 1")
    assert Decimal(assets["egg_quantity"]) == Decimal("8000.000000")


# ==================== Q7 咯哒券兑白酒：不扣底池 ====================

def _seed_wine(store, buyer_goda: str = "5000"):
    store.exec("INSERT INTO users (id, member_level) VALUES (1, 6), (2, 0)")
    store.exec("INSERT INTO user_assets (user_id, goda_coupon_balance) VALUES (2, %s)", (Decimal(buyer_goda),))
    store.exec(
        """INSERT INTO wine_jars (id, contract_no, owner_id, status)
           VALUES (1, 'YZ-HT-0001', 1, 'listed')"""
    )
    store.exec(
        """INSERT INTO wine_listings (id, listing_no, jar_id, contract_no, seller_id, status, wine_price_fen)
           VALUES (1, 'L-0001', 1, 'YZ-HT-0001', 1, 'listed', 300000)"""
    )


def test_wine_redemption_does_not_debit_pool(store):
    _seed_wine(store)
    before = store.one("SELECT * FROM system_pools WHERE id = 1")

    result = RightsService().redeem_wine_with_goda_coupons(2, 1, jars=1)

    after = store.one("SELECT * FROM system_pools WHERE id = 1")
    assert result["goda_coupon_quantity"] == "3000.000000"
    assert result["pool_coupon_debit"] == "0.000000"
    assert result["buyer_points"] == "0.000000"
    # Q7：底池券、补贴池、平台蛋库存全部不变
    assert Decimal(after["pool_coupon_balance"]) == Decimal(before["pool_coupon_balance"])
    assert Decimal(after["subsidy_coupon_balance"]) == Decimal(before["subsidy_coupon_balance"])
    assert Decimal(after["platform_egg_balance"]) == Decimal(before["platform_egg_balance"])

    assets = store.one("SELECT * FROM user_assets WHERE user_id = 2")
    assert Decimal(assets["goda_coupon_balance"]) == Decimal("2000.000000")
    jar = store.one("SELECT * FROM wine_jars WHERE id = 1")
    listing = store.one("SELECT * FROM wine_listings WHERE id = 1")
    assert int(jar["owner_id"]) == 2
    assert jar["status"] == "owned"
    assert int(jar["ownership_version"]) == 2
    assert listing["status"] == "sold"
    assert int(listing["buyer_id"]) == 2


def test_wine_quote_blocks_unconfirmed_fees_and_self_trade(store):
    _seed_wine(store)
    quote = RightsService().quote_wine_redemption(2, 1, jars=1)
    assert quote["goda_coupon_quantity"] == "3000.000000"
    assert quote["pool_coupon_debit"] == "0.000000"
    assert quote["fees"] == {"packaging_fen": None, "container_fen": None, "shipping_fen": None}
    assert quote["blocked_questions"] == ["Q13"]

    with pytest.raises(RightsError) as exc:
        RightsService().quote_wine_redemption(1, 1, jars=1)
    assert exc.value.code == "SELF_TRADE_FORBIDDEN"


def test_wine_redemption_rejects_insufficient_goda_coupons(store):
    _seed_wine(store, buyer_goda="2999")
    with pytest.raises(RightsError) as exc:
        RightsService().redeem_wine_with_goda_coupons(2, 1, jars=1)
    assert exc.value.code == "INSUFFICIENT_BALANCE"
    jar = store.one("SELECT * FROM wine_jars WHERE id = 1")
    assert int(jar["owner_id"]) == 1


# ==================== 流水 append-only ====================

def test_ledger_rejects_update_and_delete(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, egg_quantity, avg_cost_goda_value) VALUES (1, 100, 0.01)")
    store.exec(
        """INSERT INTO rights_ledger (user_id, asset_type, event_type, quantity_delta, balance_after)
           VALUES (1, 'egg', 'egg_issued', 100, 100)"""
    )
    with pytest.raises(pymysql.err.OperationalError) as update_exc:
        store.exec("UPDATE rights_ledger SET balance_after = 999 WHERE user_id = 1")
    assert update_exc.value.args[0] == 1644
    with pytest.raises(pymysql.err.OperationalError) as delete_exc:
        store.exec("DELETE FROM rights_ledger WHERE user_id = 1")
    assert delete_exc.value.args[0] == 1644
    assert len(store.all("SELECT id FROM rights_ledger")) == 1


def test_total_egg_supply_is_immutable(store):
    store.exec("UPDATE system_pools SET total_egg_supply = 200000000 WHERE id = 1")
    pools = store.one("SELECT total_egg_supply FROM system_pools WHERE id = 1")
    assert Decimal(pools["total_egg_supply"]) == TOTAL_SUPPLY


# ==================== 幂等 ====================

def test_idempotency_key_replays_same_result(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, coupon_balance) VALUES (1, 1000)")
    service = RightsService()

    first = service.exchange_eggs(1, "100", idempotency_key="key-001")
    second = service.exchange_eggs(1, "100", idempotency_key="key-001")

    assert second["exchange_id"] == first["exchange_id"]
    assert second["idempotent_replay"] is True
    assets = store.one("SELECT coupon_balance FROM user_assets WHERE user_id = 1")
    assert Decimal(assets["coupon_balance"]) == Decimal("900.000000")
    assert len(store.all("SELECT id FROM rights_ledger")) == 2


def test_idempotency_key_with_different_amount_conflicts(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, coupon_balance) VALUES (1, 1000)")
    service = RightsService()
    service.exchange_eggs(1, "100", idempotency_key="key-002")
    with pytest.raises(RightsError) as exc:
        service.exchange_eggs(1, "200", idempotency_key="key-002")
    assert exc.value.code == "IDEMPOTENCY_CONFLICT"


def test_quote_stale_when_unit_value_changed(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, coupon_balance) VALUES (1, 1000)")
    with pytest.raises(RightsError) as exc:
        RightsService().exchange_eggs(1, "100", expected_unit_value="0.02")
    assert exc.value.code == "QUOTE_STALE"


# ==================== 日结：积分→雨点→券→过期入池（Q1/Q2/Q3）+ Q12 暂缓 ====================

def test_daily_settlement_generates_rain_and_coupons(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, points) VALUES (1, 10000)")

    summary = SettlementService().run_daily_settlement(date(2026, 10, 30), points_value="0.0001")
    assert summary["status"] == "settled"
    assert summary["rain"]["rain_generated"] == "1.000000"
    assert summary["coupons"]["coupons_issued"] == "1.000000"

    assets = store.one("SELECT * FROM user_assets WHERE user_id = 1")
    # Q1 积分不清零；Q2 已转雨点从雨点余额扣除
    assert Decimal(assets["points"]) == Decimal("10000.000000")
    assert Decimal(assets["rain_balance"]) == Decimal("0")
    assert Decimal(assets["coupon_balance"]) == Decimal("1.000000")

    batch = store.one("SELECT * FROM rights_coupon_batches")
    assert batch["valid_from"] == date(2026, 10, 30)
    assert batch["valid_to"] == date(2026, 11, 29)
    assert Decimal(batch["remaining"]) == Decimal("1.000000")

    record = store.one("SELECT * FROM rights_daily_settlements WHERE business_date = '2026-10-30'")
    assert record["status"] == "settled"
    assert Decimal(record["points_value"]) == Decimal("0.0001")
    assert Decimal(record["rain_generated"]) == Decimal("1.000000")

    # 同一业务日重复执行不重复发券
    SettlementService().run_daily_settlement(date(2026, 10, 30), points_value="0.0001")
    assert Decimal(store.one("SELECT coupon_balance FROM user_assets WHERE user_id = 1")["coupon_balance"]) == Decimal("1.000000")


def test_expired_coupons_go_to_subsidy_pool_and_backfill_points(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("INSERT INTO user_assets (user_id, points) VALUES (1, 10000)")
    SettlementService().run_daily_settlement(date(2026, 10, 30), points_value="0.0001")

    store.exec("UPDATE rights_coupon_batches SET valid_to = '2026-10-30'")
    expired = SettlementService().expire_due_coupons(business_date=date(2026, 11, 1))

    assert expired["coupons_to_subsidy_pool"] == "1.000000"
    pools = store.one("SELECT * FROM system_pools WHERE id = 1")
    assets = store.one("SELECT * FROM user_assets WHERE user_id = 1")
    assert Decimal(pools["subsidy_coupon_balance"]) == Decimal("1.000000")
    assert Decimal(assets["coupon_balance"]) == Decimal("0")
    # Q3：1 券 = 1 积分回补，回补积分继续参与雨点结算
    assert Decimal(assets["points"]) == Decimal("10001.000000")
    assert store.one("SELECT status FROM rights_coupon_batches")["status"] == "expired"

    # 幂等：同一批券不会再次入池
    SettlementService().expire_due_coupons(business_date=date(2026, 11, 2))
    pools = store.one("SELECT * FROM system_pools WHERE id = 1")
    assert Decimal(pools["subsidy_coupon_balance"]) == Decimal("1.000000")


def test_subsidy_pool_never_pays_out(store):
    store.exec("INSERT INTO users (id) VALUES (1)")
    store.exec("UPDATE system_pools SET subsidy_coupon_balance = 100 WHERE id = 1")
    service = SettlementService()
    with pytest.raises(SubsidyPayoutDisabled):
        service.payout_subsidy_pool()
    summary = service.run_daily_settlement(date(2026, 10, 30), points_value="0.0001")
    assert summary["status"] == "settled"
    pools = store.one("SELECT subsidy_coupon_balance FROM system_pools WHERE id = 1")
    assert Decimal(pools["subsidy_coupon_balance"]) == Decimal("100.000000")
