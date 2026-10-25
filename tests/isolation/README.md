# Real MySQL/Redis security isolation

Execute using `python -m scripts.security_isolation.run --artifacts <absolute-path>`, not bare pytest against arbitrary services. See [execution contract](../../docs/PR220-isolation-execution.md) for prerequisites, explicit environment, native WSL/server usage, provider boundaries, evidence and exact cleanup.

Fixtures exercise the actual FastAPI routes in the same process as fault injection, plus a real loopback TCP smoke. All database business state uses real MySQL; Redis must be a dedicated instance with empty exclusive DB15. No caller-configured seed SQL, cleanup SQL, endpoint bodies or remote monkeypatch targets remain. Test results are unexecuted until the integration coordinator records them.
