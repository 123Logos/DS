# Rain Point Monthly Coupon Policy

## Assessment

The existing `users.true_total_points` field is the available rain-point balance. Existing coupon expiry settlement is transactional and already writes an equivalent amount to `member_points`; this feature extends that flow instead of creating a second balance system.

The existing `director_pool` account is used by the unilevel dividend distribution, so it is the implementation mapping for the requested dividend pool. Legacy coupons without a rain-point settlement reference continue to settle into `subsidy_pool`.

## Rules

For each normal member, once per `YYYY-MM` period:

1. Balance greater than 330: convert `balance - 330` into one user coupon.
2. Balance from 0 through 330: convert `min(balance, 30)` into one user coupon.
3. The converted rain points are deducted atomically from `true_total_points`.
4. The coupon is valid from the first day through the last day of the settlement month. An unused coupon is marked expired after that month.
5. An expired rain-point coupon is credited to `director_pool` and the same amount is added to `users.member_points`, with a `points_log` entry.
6. A unique `(user_id, settlement_period)` key makes retries idempotent. A zero balance still creates a zero-value settlement record and no coupon.

## Deployment

Run `migrations/003_rain_point_monthly_coupon.sql` before enabling the scheduler. `database_setup.py` contains the same schema for new installations and startup schema checks add the coupon reference column to existing installations.

The scheduler runs at 00:05 on the first day of each month. The existing 23:58 expiry task settles the prior month's unused coupons. Both tasks are protected by the existing scheduler process lock.

## Verification

Test the three boundary balances (0, 30, 330), an excess balance (331 or more), duplicate execution for the same month, concurrent execution, coupon expiry routing, and rollback when any insert/update fails. Production rollout should first run the migration and then inspect the monthly settlement and account-flow reports.

## Change Checklist

- [x] Add 330 base and 30 monthly policy constants.
- [x] Add a unique monthly settlement ledger and coupon reference.
- [x] Add transactional conversion and idempotent retry handling.
- [x] Route policy coupon expiry to `director_pool` and credit member points.
- [x] Schedule conversion on day 1 at 00:05.
- [x] Add migration and boundary tests.
