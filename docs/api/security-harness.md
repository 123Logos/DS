# Security harness contract

## Public API changes

None. No new HTTP route, request parameter, response field, test header or production bypass is introduced by the harness. Existing business authentication/payment/content/finance API contracts belong to `security-auth.md`, `security-payments.md`, `security-content.md` and `security-finance.md` as applicable. Front-end changes: none for this slice.

## Local execution interface

`python -m scripts.security_isolation.run --artifacts <absolute-directory> [pytest-options]` runs bootstrap, the full `tests/` suite and finally cleanup. Required environment inputs: `MYSQL_HOST`, integer `MYSQL_PORT`, `MYSQL_USER`, `MYSQL_PASSWORD` (may be empty only on an explicitly isolated service), `REDIS_HOST`, integer `REDIS_PORT`, and exact `SECURITY_ISOLATION_ACK=dedicated-services-no-production`. Optional `REDIS_PASSWORD` authenticates the dedicated Redis. There is no HTTP URL, method, request body or response body for this local CLI.

The command generates a unique database name and artifact subdirectory. It does not accept caller-controlled SQL or an existing database name. Redis DB15 must be empty and exclusively reserved for one run. A missing required variable/acknowledgement produces argparse failure before schema access. Unsafe lifecycle settings, ownership mismatch, dependency failure or outbound provider connection fail closed. Exit0 is possible only after pytest and cleanup both exit0; `exit.json` retains their separate outcomes, while bootstrap errors propagate as command failures. No tests are claimed executed by this document.

## Resource and evidence semantics

Actual application routes are served in the same process as test-only provider/fault instrumentation; database transactions use real MySQL. Loopback HTTP transport has bounded startup/shutdown and no public bypass. Provider simulations are explicitly `CONTROLLED_BOUNDARY_ONLY` and never establish real SMS delivery or payment/refund acceptance. Logs/JUnit/numeric database invariants are retained outside source. Generated database cleanup verifies its ownership marker; Redis cleanup verifies the exclusive run marker. No production service may be supplied even if the naming guard would pass.

See [execution guide](../PR220-isolation-execution.md) for full setup, exact invocation, artifacts, failure recovery, migration ordering, and operational constraints.

## Change record

Replaced configurable remote URL/SQL placeholders with candidate-owned executable fixtures, guarded bootstrap, same-process fault injection, real TCP smoke and exact generated-resource cleanup. The old `ISOLATED_*_SQL`, `ISOLATED_*_URL`, body and patch-target settings are removed, not compatibility aliases. Operators must adopt the generated-resource runner; arbitrary production or pre-seeded remote endpoints are intentionally unsupported.
