from decimal import Decimal

BASE = Decimal('330')
MONTHLY_AMOUNT = Decimal('30')


def calculate_conversion(balance: Decimal) -> tuple[Decimal, str]:
    balance = max(Decimal('0'), Decimal(str(balance)))
    if balance > BASE:
        return balance - BASE, 'excess'
    return min(balance, MONTHLY_AMOUNT), 'monthly'
