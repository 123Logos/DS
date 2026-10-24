# PR #219 最小止血补丁验证记录

日期：2026-10-24
分支：`hotfix/msg-sec-check-minimal`
止血 commit：`bc428ff fix(sec): fail-closed on malformed avatar review callback`

## 实际执行的完整命令

```powershell
uv run pytest -q tests/test_avatar_moderation_service.py tests/test_msg_sec_check.py tests/test_profile_text_security.py 2>&1 | Tee-Object -FilePath "$env:TEMP\219-hotfix-test.log"; exit $LASTEXITCODE
```

```powershell
uv run python -m compileall -q services/avatar_moderation_service.py tests/test_avatar_moderation_service.py 2>&1 | Tee-Object -FilePath "$env:TEMP\219-hotfix-lint.log"; exit $LASTEXITCODE
```

仓库 `pyproject.toml` 未配置专用 lint/vet 命令；第二条命令是本次变更文件的 Python 语法验证，不等同于完整 lint。

## 结果摘要

- 测试：**通过，43 passed**。
- 测试失败：0。
- 语法验证：**通过**，命令退出码 0。
- 测试警告：13 个既有 Pydantic 弃用警告；不由本次改动引入，未修改相关代码。
- 新增行为覆盖：缺失 `errcode` 且 `suggest=pass` 的头像审核回调被标记为 `failed`，不会进入头像公开写入的 `pass` 分支。
- 已覆盖的相关拒绝行为：头像 risky 回调、文本审核上游异常/未知结果、资料写入未通过审核、缺失 openid、认证及输入边界。

## 失败项及原因

无测试失败项。

## 未验证边界

以下项目未在本地执行，均为**待隔离环境验证**：

- 并发核销：待隔离环境验证。
- JWT 撤销：待隔离环境验证。
- 订单状态竞争：待隔离环境验证。
- MySQL/Redis 双连接：待隔离环境验证。
- 退款“外部成功本地失败”：待隔离环境验证。
- 真实微信头像异步审核回调签名、报文兼容性及授权配置：待隔离环境验证。
- 真实微信文本审核及 Unicode/2500 字边界：待隔离环境验证。
- 真实短信、微信支付/退款及生产回调：待隔离环境验证。

本次未部署生产、未进行生产故障注入、未发送真实短信、未发生支付或退款。
