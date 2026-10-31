"""V1.1 权益核心逻辑单元测试（纯计算，不依赖数据库）。

覆盖：Q6 咯哒值口径、R3/R4 兑换分流、Q4 加权平均与触发线、Q5 转券数量、
Q7 兑酒不扣底池、Decimal 精度、Q12 暂缓的源码级约束。
"""
import re
from datetime import date
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

import pytest

from services.rights_service import (
    GODA_COUPONS_PER_JAR,
    MAX_WINE_JARS_PER_OPERATION,
    RightsError,
    compute_unit_value,
    conversion_triggered,
    eggs_for_coupons,
    goda_coupons_for_eggs,
    goda_coupons_for_jars,
    quantize_amount,
    split_submission,
    to_decimal,
    weighted_avg_cost,
)
from services.settlement_service import (
    COUPON_VALID_DAYS,
    MAX_DAILY_POINTS_VALUE,
    SubsidyPayoutDisabled,
    SettlementService,
    coupon_validity,
    daily_points_value,
    rain_for_points,
)

ROOT = Path(__file__).resolve().parent.parent


# ==================== Q6 实时咯哒值 ====================

def test_initial_unit_value_matches_requirement():
    """需求 3.1/3.4：底池 100 万 ÷ 平台 1 亿 = 0.01。"""
    assert compute_unit_value(Decimal("1000000"), Decimal("100000000")) == Decimal("0.010000")


def test_unit_value_is_none_when_platform_inventory_empty():
    """分母为 0 时必须返回 None，不能用 0 冒充已计算。"""
    assert compute_unit_value(Decimal("1000000"), Decimal("0")) is None
    assert compute_unit_value(Decimal("1000000"), Decimal("-1")) is None


def test_unit_value_uses_six_decimal_round_half_up():
    expected = (Decimal("1234567") / Decimal("9876543")).quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    value = compute_unit_value(Decimal("1234567"), Decimal("9876543"))
    assert value == expected
    assert value.as_tuple().exponent == -6


# ==================== R3/R4 兑换分流与数量 ====================

def test_requirement_example_100_coupons_yields_8000_eggs():
    """需求 3.4：提交 100 券，80 入底池、20 入补贴池、按 0.01 得 8,000 枚。"""
    pool_in, subsidy_in = split_submission(Decimal("100"))
    assert (pool_in, subsidy_in) == (Decimal("80.000000"), Decimal("20.000000"))
    assert eggs_for_coupons(pool_in, Decimal("0.01")) == Decimal("8000.000000")


def test_split_never_loses_dust():
    """80/20 拆分必须闭合：底池 + 补贴池 == 提交量（最小单位也没有尾差）。"""
    for raw in ("0.000001", "0.000003", "7", "333.333333", "999999999.999999"):
        pool_in, subsidy_in = split_submission(Decimal(raw))
        assert pool_in + subsidy_in == Decimal(raw)
        assert subsidy_in >= 0


def test_split_rejects_non_positive_quantity():
    for raw in ("0", "-1"):
        with pytest.raises(RightsError) as exc:
            split_submission(Decimal(raw))
        assert exc.value.code == "INVALID_ARGUMENT"


def test_eggs_for_coupons_quantizes_half_up():
    assert eggs_for_coupons(Decimal("0.1"), Decimal("0.03")) == Decimal("3.333333")
    assert eggs_for_coupons(Decimal("1"), Decimal("3")) == Decimal("0.333333")


# ==================== Q4 加权平均成本 ====================

def test_weighted_average_cost_matches_q4_formula():
    """(8000×0.01 + 4000×0.015) / 12000 = 0.011666... -> 0.011667。"""
    cost = weighted_avg_cost(Decimal("0.01"), Decimal("8000"), Decimal("0.015"), Decimal("4000"))
    assert cost == Decimal("0.011667")


def test_weighted_average_cost_first_purchase_equals_purchase_price():
    assert weighted_avg_cost(Decimal("0"), Decimal("0"), Decimal("0.01"), Decimal("8000")) == Decimal("0.010000")


def test_weighted_average_cost_resets_without_holding():
    assert weighted_avg_cost(Decimal("0.01"), Decimal("0"), Decimal("0.02"), Decimal("0")) == Decimal("0")


# ==================== Q4 触发线 / Q5 转券数量 ====================

def test_conversion_boundary_is_exactly_double():
    cost = Decimal("0.01")
    assert conversion_triggered(Decimal("0.02"), cost) is True
    assert conversion_triggered(Decimal("0.019999"), cost) is False
    assert conversion_triggered(None, cost) is False
    assert conversion_triggered(Decimal("1"), Decimal("0")) is False


def test_conversion_quantity_matches_q4_example():
    """Q4 算例：8000 枚蛋在咯哒值 0.02 时转 160 咯哒券。"""
    assert goda_coupons_for_eggs(Decimal("8000"), Decimal("0.02")) == Decimal("160.000000")


# ==================== Q7 白酒兑换比例 ====================

def test_goda_coupons_per_jar_is_3000():
    assert GODA_COUPONS_PER_JAR == Decimal("3000")
    assert goda_coupons_for_jars(1) == Decimal("3000.000000")
    assert goda_coupons_for_jars(3) == Decimal("9000.000000")


def test_goda_coupons_reject_out_of_range_jars():
    with pytest.raises(RightsError):
        goda_coupons_for_jars(0)
    with pytest.raises(RightsError):
        goda_coupons_for_jars(MAX_WINE_JARS_PER_OPERATION + 1)
    with pytest.raises(RightsError):
        goda_coupons_for_jars(True)


# ==================== Decimal 精度 ====================

def test_decimal_rejects_float_input():
    with pytest.raises(RightsError) as exc:
        to_decimal(0.1, "coupon_quantity")
    assert exc.value.code == "INVALID_ARGUMENT"


def test_decimal_rejects_nan_and_bool():
    with pytest.raises(RightsError):
        to_decimal("NaN")
    with pytest.raises(RightsError):
        to_decimal(True)


def test_decimal_sum_is_exact_no_binary_float_error():
    """0.1 + 0.2 在 float 下为 0.30000000000000004，Decimal 必须精确闭合。"""
    total = to_decimal("0.1") + to_decimal("0.2")
    assert total == Decimal("0.3")
    assert quantize_amount(total) == Decimal("0.300000")


def test_rights_service_source_has_no_float_arithmetic():
    source = (ROOT / "services" / "rights_service.py").read_text(encoding="utf-8")
    assert "float(" not in source
    assert "round(" not in source


# ==================== 结算：Q1/Q2/Q3 ====================

def test_daily_points_value_is_capped():
    assert daily_points_value(Decimal("100"), Decimal("1000000")) == Decimal("0.0001")
    assert daily_points_value(Decimal("1000000"), Decimal("100")) == MAX_DAILY_POINTS_VALUE


def test_daily_points_value_zero_when_no_points_or_no_funding():
    assert daily_points_value(Decimal("100"), Decimal("0")) == Decimal("0")
    assert daily_points_value(Decimal("0"), Decimal("1000")) == Decimal("0")
    assert daily_points_value(Decimal("-5"), Decimal("1000")) == Decimal("0")


def test_rain_for_points_uses_half_up():
    assert rain_for_points(Decimal("10000"), Decimal("0.00005")) == Decimal("0.500000")
    assert rain_for_points(Decimal("10000"), Decimal("0")) == Decimal("0")


def test_coupon_validity_is_30_days():
    start, end = coupon_validity(date(2026, 10, 31))
    assert start == date(2026, 10, 31)
    assert (end - start).days == COUPON_VALID_DAYS


# ==================== Q12 强制暂缓 ====================

def test_subsidy_payout_is_disabled():
    with pytest.raises(SubsidyPayoutDisabled):
        SettlementService().payout_subsidy_pool()


def test_settlement_source_has_no_subsidy_payout_arithmetic():
    """源码级兜底：不得出现补贴池出池扣减，也不得出现 12%/8% 比例常量。"""
    source = (ROOT / "services" / "settlement_service.py").read_text(encoding="utf-8")
    assert "subsidy_coupon_balance = subsidy_coupon_balance -" not in source
    assert 'Decimal("0.12")' not in source
    assert 'Decimal("0.08")' not in source
    assert '"0.12"' not in source
    assert '"0.08"' not in source
    # 补贴池只允许出现一次增量写（券过期入池）
    assert source.count("subsidy_coupon_balance = subsidy_coupon_balance +") == 1


def test_rights_service_debits_pool_only_for_conversion():
    """Q7：兑酒流程不得扣底池；底池扣减只允许出现在转券（Q5）。"""
    source = (ROOT / "services" / "rights_service.py").read_text(encoding="utf-8")
    assert source.count("pool_coupon_balance = pool_coupon_balance -") == 1
    assert '"pool_coupon_debit": format_amount(Decimal("0"))' in source


# ==================== 漏洞 1 & 2：积分/雨点的唯一写入点 ====================

_DIRECT_ASSET_WRITE = re.compile(
    r"(UPDATE\s+user_assets\b.{0,400}?\b(points|rain_balance)\s*="
    r"|INSERT\s+(?:IGNORE\s+)?INTO\s+user_assets\s*\([^)]*\b(points|rain_balance)\b)",
    re.IGNORECASE | re.DOTALL,
)

#: 只有这两处可以直接写镜像列：桥接（补建缺失行）与历史迁移脚本（建立初始镜像）
_ASSET_WRITE_ALLOWED = {
    "services/legacy_assets_bridge.py",
    "scripts/migrate_legacy_assets.py",
}


def test_mirrored_columns_have_single_writer():
    """user_assets.points / rain_balance 是 users 的镜像，业务代码不得直接写。

    触发器已经在 users 变化时镜像增量，若业务代码再写一次镜像列，同一笔增量
    会被记两次，新老账本立刻分叉。这里做源码级封堵，防止后续新增路径重新踩坑。
    """
    scanned = list((ROOT / "services").rglob("*.py")) + list((ROOT / "api").rglob("*.py")) + list((ROOT / "scripts").glob("*.py"))
    assert scanned, "扫描范围为空，检查路径"

    offenders = []
    for path in scanned:
        relative = path.relative_to(ROOT).as_posix()
        if relative in _ASSET_WRITE_ALLOWED:
            continue
        text = path.read_text(encoding="utf-8")
        for match in _DIRECT_ASSET_WRITE.finditer(text):
            line_no = text.count("\n", 0, match.start()) + 1
            offenders.append(f"{relative}:{line_no}")
    assert offenders == [], f"发现直接写镜像列，应改为写 users 由触发器镜像: {offenders}"


def test_bridge_module_is_the_only_legacy_writer():
    """桥接模块必须存在且只写 users 侧积分列，不写镜像列。"""
    source = (ROOT / "services" / "legacy_assets_bridge.py").read_text(encoding="utf-8")
    assert "member_points" in source and "true_total_points" in source
    assert "float(" not in source
    # 唯一允许直接落镜像的地方是补建缺失行，且带 INSERT IGNORE
    assert source.count("INSERT IGNORE INTO user_assets") == 1


# ==================== 加锁顺序（pools -> users -> user_assets） ====================

def _function_blocks(source: str) -> dict[str, str]:
    """按 4 空格缩进的 ``def`` 切分模块，返回 {函数名: 函数体文本}。"""
    blocks: dict[str, str] = {}
    pattern = re.compile(r"^    def (\w+)", re.MULTILINE)
    matches = list(pattern.finditer(source))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(source)
        blocks[match.group(1)] = source[match.start():end]
    return blocks


def test_asset_writes_lock_users_before_user_assets():
    """凡是拿 user_assets 行锁的写方法，必须先拿 users 行锁。

    镜像触发器 trg_users_assets_mirror_update 的执行路径是 users → user_assets，
    旧业务也是这个方向。新代码若只拿 user_assets 而不同时拿 users，
    一旦后续在事务里回头写 users 就与旧业务形成环路 —— 死锁只会在生产并发下出现，
    所以在这里做源码级封堵。
    """
    source = (ROOT / "services" / "rights_service.py").read_text(encoding="utf-8")
    blocks = _function_blocks(source)
    assert "exchange_eggs" in blocks and "maybe_auto_convert" in blocks

    offenders = []
    checked = 0
    for name, body in blocks.items():
        if "lock_user_assets(cur, user_id)" not in body:
            continue
        checked += 1
        asset_lock = body.index("lock_user_assets(cur, user_id)")
        users_lock = body.find("lock_legacy_user(cur, user_id)")
        pools_lock = body.find("lock_pools(cur)")
        if users_lock < 0 or users_lock > asset_lock:
            offenders.append(f"{name}: 缺少/晚于 user_assets 的 users 行锁")
        if pools_lock >= 0 and pools_lock > users_lock:
            offenders.append(f"{name}: system_pools 应在 users 之前加锁")
    assert checked >= 3, f"应至少检查 3 个写方法，实际 {checked}"
    assert offenders == [], f"加锁顺序违规: {offenders}"


def test_lock_helpers_document_the_order():
    """三个加锁入口的 docstring 必须写明它在全局顺序中的位置。"""
    source = (ROOT / "services" / "rights_service.py").read_text(encoding="utf-8")
    blocks = _function_blocks(source)
    assert "第 1 步" in blocks["lock_pools"]
    assert "第 2 步" in blocks["lock_legacy_user"] and "users" in blocks["lock_legacy_user"]
    assert "第 3 步" in blocks["lock_user_assets"]

