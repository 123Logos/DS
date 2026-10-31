# PR220 isolated security execution

This is a runnable verification harness, not a record of successful execution. The coordinator executes validation after integration. It never authorizes production SMS, money movement, production data access, service restarts or changes to business policy.

## Preconditions

Use a native Linux/WSL Python >=3.13 with project dependencies and `pytest` (`uv sync --extra dev`). Use dedicated MySQL 8 and Redis 7 instances, bound to loopback or a private isolated network. Existing production MySQL/Redis instances are not acceptable even with a different database number. The MySQL account requires create/drop and schema DDL/DML only for `dsiso\_%` databases; it must have no production grants. Redis DB15 must be empty and exclusively dedicated to this invocation. Concurrent harness invocations must use different service instances.

Do not source production `.env`. Supply credentials through a private environment file supplied by the coordinator (not committed, printed or included in artifacts). The runner changes working directory to a newly generated artifact directory, disables python-dotenv, generates JWT/SMS secrets, removes provider environment variables and blocks outbound network in bootstrap and the tested Python process. Only configured MySQL/Redis addresses and explicitly registered test-owned loopback HTTP listeners are permitted. No mock business database or business service is used. SMS/refund/moderation adapters, where replaced at their provider boundary, are labelled `CONTROLLED_BOUNDARY_ONLY`; these do not prove actual provider delivery or compatibility.

## Exact invocation (same on WSL and isolated server candidate)

```sh
# Set MYSQL_HOST MYSQL_PORT MYSQL_USER MYSQL_PASSWORD REDIS_HOST REDIS_PORT
# and optional REDIS_PASSWORD using the private isolated runtime environment.
export SECURITY_ISOLATION_ACK=dedicated-services-no-production
uv run --extra dev python -m scripts.security_isolation.run --artifacts /home/ll/ds-security-evidence
```

Run from the candidate worktree, never the original dirty workspace or live server directory. When dependencies are already synchronized, the equivalent interpreter command is `python -m scripts.security_isolation.run --artifacts <absolute-output-directory>`. Additional pytest options such as `-k refund` may be appended; a subset is not full acceptance evidence.

The runner collects the entire `tests/` tree, including original regression tests. A pytest plugin installs the same egress guard before collection/import side effects. Bytecode and pytest cache generation are disabled (`PYTHONDONTWRITEBYTECODE=1`, `-p no:cacheprovider`) so source copies remain untouched. New isolation fixtures additionally capture per-business-test invariants.

The runner chooses a fresh `dsiso_<16 random hex>` database; it cannot be selected by arbitrary caller SQL. It forces `ENVIRONMENT=test`, `SKIP_STARTUP_DDL=true`, `RUN_MIGRATE_ON_STARTUP=false`, `ENABLE_BACKGROUND_TASKS=false`, pool size6 and one worker. `main.py` validates those isolation flags, database identity and acknowledgement before startup. Route registration must not start background tasks. Normal production lifecycle defaults are unchanged; direct `python main.py` no longer performs an extra pre-lifecycle DDL pass.

Bootstrap creates an ownership marker, initializes actual application schema and runs all numbered migrations in lexical order. The migration runner records file SHA256 in `schema_migrations`, applies each version once and rejects later edits to an applied version. This is essential because migration004 intentionally invalidates legacy sessions. DDL is bootstrap-only; MySQL DDL is not claimed to be rollback-safe. A failed fresh bootstrap is discarded by exact database cleanup, not repaired through guessed SQL.

## Evidence and cleanup

Each run directory retains:

- `run.json`: generated identity and explicit provider evidence label (no credentials).
- `bootstrap.log`, `environment.json`: schema activity and actual MySQL version/isolation/SQL mode/charset plus Redis version.
- `pytest.log`, `junit.xml`: real stdout/stderr and pytest JUnit.
- `evidence.jsonl`: per-test before/after table counts and numeric asset sums; scenario-specific connection IDs, statuses and invariants. The synthetic authentication table values are not serialized.
- `cleanup.log`, `cleanup.json`, `exit.json`: exact owner-checked drop, Redis remaining-key count and separate test/cleanup exit codes. Cleanup failure does not erase the original test exit code.

Cleanup executes in the runner's `finally` path and drops only its generated database with a matching ownership row. It deletes keys only if the reserved Redis ownership marker matches. Never use arbitrary cleanup SQL, FLUSHALL, shared-resource wildcard deletion or production seed queries. A hard-killed runner cannot execute `finally`: retain `run.json`, investigate ownership and use the same isolated environment to invoke `python -m scripts.security_isolation.bootstrap drop` with that exact run ID/database/resource directory. Do not remove evidence files.

## Test interfaces and scope

`db()` opens real independent DictCursor MySQL connections with rollback/close in `finally`. `http` is FastAPI TestClient against the actual registered application in the same process as injected faults; it is not remote HTTP accidentally patched in a different process. `test_http_transport.py` additionally runs a bounded real loopback uvicorn listener and HTTP request with deterministic startup notification and shutdown. `race(*actions)` starts bounded parallel actions behind a barrier; stock tests additionally synchronize actual business DB connections and record distinct `CONNECTION_ID()` values before either proceeds. No sleep is used to pretend requests overlapped.

Tests cover real coupon balance/idempotency competition and shared-key denial, last-stock authoritative-price HTTP competition, durable refund external-accepted/local-commit-failure then query recovery and signed RSA/AES callback replay, unsigned callback refusal, actual MySQL/Redis identity and TCP transport. Auth/content owners contribute their actual HTTP behavior scenarios using these same fixtures; transition coverage is maintained with the payment owner. Missing scenarios or failing checks must remain explicitly open in the coordinator acceptance report, not be represented by environmental SQL placeholders or mere successful status codes.

## API/front-end impact

No public test/fault/configuration HTTP API is introduced. There is no bypass header, test refund route or production signature relaxation. Existing business API changes are documented by their owners in `docs/api/security-*.md`. Harness command inputs are local process environment/CLI only; missing acknowledgement/connection inputs or unsafe lifecycle configuration fail before business execution.
