# PR218 security remediation verification report — 2026-10-25

## Status

**Candidate verification completed for the final recorded WSL and confined-server round 4 suites, not overall security/provider or rollout acceptance.** Both suites passed against the same archived candidate snapshot. This does not establish live deployment state or real external provider behavior, and does not declare every risk closed. No build/lint/formatter/manual production smoke is claimed. This report does not authorize rollout or production activity.

Candidate worktree: `E:/redspider/DS-security-remediation-20261025`, branch `fix/pr218-security-completion`; stated baseline `4249ff604b2d2caebb6138ba21fdd5400903f239`. The live server path was explicitly not modified; production mutations and external real transactions were not authorized (`run-metadata.json`).

## Baseline probe evidence (pre-remediation only)

The following results are from the baseline source, not the candidate. Each record reports a generated isolated database and `cleanup_database_absent: true`; provider calls were zero.

| Probe | WSL result | Isolated server result | Interpretation |
| --- | --- | --- | --- |
| Actual `confirm_receive` SELECT, second real DB connection commits refunding, then actual UPDATE | `baseline-order-race.json`: connections 17/18; interleaved refund committed; receipt returned `ok:true`; final status `completed`; `security_expectation_met:false` | `server-baseline-order-race.json`: connections 12/13; interleaved refund committed; receipt returned `ok:true`; final status `completed`; `security_expectation_met:false` | Baseline demonstrated a confirmation/refund race overwriting the refunding state. It says nothing about candidate behavior. |
| Issue JWT, validate, invalidate session, validate same JWT | `baseline-jwt-revocation.json`: initial user 900001; `invalidate_result:false`; subsequent validation `ACCEPTED`; `security_expectation_met:false` | `server-baseline-jwt-revocation.json`: initial user 900001; `invalidate_result:false`; subsequent validation `ACCEPTED`; `security_expectation_met:false` | Baseline demonstrated that this old JWT remained accepted after attempted invalidation. It says nothing about candidate behavior. |

The two order probe files report the same method SHA-256 `b04c744d485053aebc1a2b57af983581e85f9527a0e0c6a3d10b26735cb633fb`. Exact JSON files are retained in the evidence directory; the compact values above are copied from those records, not inferred test totals.

## Isolated infrastructure observations

`wsl-infrastructure.json`: Linux, native Python path recorded separately; MySQL 8.0.45, `REPEATABLE-READ`, `utf8mb4`, `utf8mb4_0900_ai_ci`, strict SQL mode; two visible databases (`information_schema`, `performance_schema`); Redis ping succeeded.
`server-infrastructure.json`: Linux, Python 3.14.3; MySQL 8.0.45-0ubuntu0.24.04.1 with `REPEATABLE-READ`, `utf8mb4`, `utf8mb4_0900_ai_ci`, strict SQL mode; two visible databases (`information_schema`, `performance_schema`); Redis 7.0.15 ping succeeded.
- `run-metadata.json` records isolated test service ports 23306/26379, separate WSL/server test paths, and no authorization for production mutations or external real transactions. Credentials are not included here.

These are infrastructure snapshots; candidate-suite results are reported separately below. Infrastructure availability alone is not acceptance evidence.

## Candidate verification — final round 4 WSL and confined-server suites passed

Both final candidate runs used the same archived source SHA-256 `5847fe1856fb7345537b19c9338eff5a384601e9c594ec2a9a2ac847eebad391` reported by the coordinator. The final expanded suite included the two reviewer-requested log canary cases. WSL artifacts: `E:/redspider/DS-security-evidence-20261025/wsl/dsiso_345823e141914922/`; server artifacts: `E:/redspider/DS-security-evidence-20261025/server-final/` (run id `dsiso_05a1c8b6dd77cca5`).

| Environment/run | MySQL / Redis | Pytest / JUnit | Exit and cleanup | Scope |
| --- | --- | --- | --- | --- |
| WSL final round 4 (`dsiso_345823e141914922`) | MySQL `8.0.45`, `REPEATABLE-READ`, `utf8mb4`, strict SQL mode; Redis `7.4.11` | 141 tests, 141 passed, 0 failures, 0 errors, 0 skipped; 137 warnings; 76.088 seconds | `exit.json`: test exit 0, cleanup exit 0; `cleanup.json`: `errors: []` | Isolated candidate suite and its recorded assertions only. |
| Confined server final round 4 (`dsiso_05a1c8b6dd77cca5`) | MySQL `8.0.45-0ubuntu0.24.04.1`, `REPEATABLE-READ`, `utf8mb4`, strict SQL mode; Redis `7.0.15` | 141 tests, 141 passed, 0 failures, 0 errors, 0 skipped; 137 warnings; 86.421 seconds | `exit.json`: test exit 0, cleanup exit 0; `cleanup.json`: `errors: []` | Confined isolated candidate suite only. Not the live production deployment. |

Final cleanup evidence (`E:/redspider/DS-security-evidence-20261025/final-cleanup-summary.json`) records WSL test containers stopped, server test units inactive/dead, production service active, zero production source changes across 90 checked files, no remaining test databases, zero Redis DB15 test keys, and no private-key or bytecode files in the evidence tree. `final-wsl-resource-cleanup.json` independently records no remaining test databases, zero Redis DB15 keys, and `clean:true`. Runtime copies and redacted evidence remain retained for reproducibility. These are teardown and source-preservation checks, not an auto-deploy or proof that production runs the candidate; no deployment was performed or claimed.

Earlier runs are retained as history, not final results: round 1 had 37 failures/82 passes; round 2 had 5 failures/133 passes; round 3 had 140 passes in each environment. Round 4 supersedes those results for the expanded snapshot. WSL Redis `7.4.11` and server Redis `7.0.15` differ; the environments are not identical.


## Implementation contracts and remaining boundaries

Current slice contracts, not historical prose in older documents, are authoritative:

- [Authentication, SMS reset, operator mutations and privacy](api/security-auth.md). Migration `004_security_auth.sql` explicitly invalidates legacy sessions once; session-backed tokens require `sid`, and `users.token` is not an authentication fallback. No manual database insertion of password reset challenges. Real SMS credentials, entitlement, delivery, and receipt validation are unavailable; missing configuration fails closed. A controlled adapter boundary is not proof of real supplier delivery.
- [Orders, payments and refunds](api/security-payments.md). Migration `005_security_payments.sql`; the final isolated suite exercised controlled refund acceptance/local-commit-failure recovery, callback signature/replay, late/cancelled/offline payment quarantine, and legacy refund reconciliation cases documented by the owner. These verify local application/database control flow for the recorded scenarios only. They do not establish real WeChat payment/refund/query/signature/wallet-transfer compatibility or money movement. Legacy in-flight cases remain quarantined pending provider-backed operator reconciliation.
- [Finance authorization, idempotency and transaction interfaces](api/security-finance.md). Migration `006_security_finance.sql`. Merchant bankcard withdrawal is not integrated: the protected endpoint returns 503 before creating an application or debiting assets. Existing wallet batch transfer is a different product.
- [Content review and final product snapshot](api/msg-sec-check.md). Nested public strings/keys are reviewed individually, each with Python `len()` maximum 2500; stale reviewed snapshots conflict with HTTP 409 without writes. Real WeChat behavior and provider Unicode boundary equivalence remain unverified.
- [Isolated harness](api/security-harness.md). The harness uses real isolated MySQL/Redis and the actual app, with controlled test-only provider-boundary instrumentation explicitly labelled `CONTROLLED_BOUNDARY_ONLY`; it is not real external provider evidence or an OS sandbox for arbitrary untrusted native subprocesses.

Front-end source was not included in this assignment and has not been migrated or device-validated. Read-only checks observed the live service active, tested server process confined away from the live source, and 90 live source hashes unchanged; this is not a full security-exposure audit and does not establish which candidate revision is deployed. No automatic deployment occurred. Existing requirements Q1–Q17, monthly 330/30 settlement and daily subsidy policies, and asset policy were not changed. Goda egg/coupon and wine-jar contract trading remain unimplemented business targets.

## Evidence files

- Baseline metadata and probes: `run-metadata.json`, `wsl-infrastructure.json`, `server-infrastructure.json`, `baseline-order-race.json`, `server-baseline-order-race.json`, `baseline-jwt-revocation.json`, `server-baseline-jwt-revocation.json` under `E:/redspider/DS-security-evidence-20261025/`.
- Final source archive SHA-256: `5847fe1856fb7345537b19c9338eff5a384601e9c594ec2a9a2ac847eebad391`.
- Final WSL artifacts: `E:/redspider/DS-security-evidence-20261025/wsl/dsiso_345823e141914922/`.
- Final confined-server artifacts: `E:/redspider/DS-security-evidence-20261025/server-final/`.

The final run included registration/referral and signed-callback failure logging canaries. The registration/referral canary exercised the actual referral service path; it was not an HTTP route test. Results do not prove every unexercised log branch safe. Candidate test evidence is specific to the archived manifest and suite; baseline results remain separate.
