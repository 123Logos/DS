import pytest
from fastapi import HTTPException
from services.refund_service import validate_refund_fee


@pytest.mark.parametrize('value', [0, -1, 101, True, False, 1.5, '1'])
def test_refund_fee_rejects_nonpositive_noninteger_or_excess(value):
    with pytest.raises(HTTPException) as error:
        validate_refund_fee(value, 100)
    assert error.value.status_code == 422


def test_default_and_partial_refund_amounts():
    assert validate_refund_fee(None, 100) == 100
    assert validate_refund_fee(1, 100) == 1
    assert validate_refund_fee(None, 0) == 0
