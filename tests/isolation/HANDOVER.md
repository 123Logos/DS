# Isolation handover

The previous configurable SQL/remote URL placeholders have been removed. Follow [the complete execution and cleanup contract](../../docs/PR220-isolation-execution.md).

Run `uv run --extra dev python -m scripts.security_isolation.run --artifacts <absolute-directory>` from the candidate with explicit dedicated MySQL/Redis environment and `SECURITY_ISOLATION_ACK=dedicated-services-no-production`. Never use production `.env`, services, certificates, SMS or money. The runner owns bootstrap, real-app startup, JUnit/stdout/invariant capture and owner-checked finally cleanup. Provider adapters are controlled-boundary evidence only.

Report the generated run ID, exact command, test and cleanup exit codes, environment versions, connection identities, scenario assertions and retained artifact path. A failure or absent real provider proof is not a pass. Do not fix test failures by configuring arbitrary queries, changing business policy or weakening assertions.
