from decimal import Decimal

from services.finance.rain_point_policy import calculate_conversion


def test_monthly_conversion_boundaries():
    assert calculate_conversion(Decimal("0")) == (Decimal("0"), "monthly")
    assert calculate_conversion(Decimal("30")) == (Decimal("30"), "monthly")
    assert calculate_conversion(Decimal("330")) == (Decimal("30"), "monthly")
    assert calculate_conversion(Decimal("331")) == (Decimal("1"), "excess")


def test_negative_balance_never_creates_coupon():
    assert calculate_conversion(Decimal("-1")) == (Decimal("0"), "monthly")
