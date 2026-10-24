关联：#219

## 范围

本 PR 只包含 03 方案下的最小 fail-closed 止血补丁，不缩减 #219 原验收范围，也不宣称九条未完成项或六条前端影响项已完成。

## 改动与理由

- `services/avatar_moderation_service.py`：头像异步审核回调不再使用 `or 0` 把缺失、空值或布尔 `errcode` 当成成功。
- 缺少严格整数 `errcode` 的回调现在进入 `failed`，因此不能因 `suggest=pass` 触发头像公开写入。
- 新增回归测试覆盖缺少 `errcode` 但带 `suggest=pass` 的 fail-open 场景。
- 未修改公共接口签名、数据库结构、依赖版本、短信、JWT、支付、退款或订单状态逻辑。

## 本地验证

执行：

```powershell
uv run pytest -q tests/test_avatar_moderation_service.py tests/test_msg_sec_check.py tests/test_profile_text_security.py 2>&1 | Tee-Object -FilePath "$env:TEMP\219-hotfix-test.log"; exit $LASTEXITCODE
```

结果：43 passed，0 failed；13 个既有 Pydantic 弃用警告。

执行：

```powershell
uv run python -m compileall -q services/avatar_moderation_service.py tests/test_avatar_moderation_service.py 2>&1 | Tee-Object -FilePath "$env:TEMP\219-hotfix-lint.log"; exit $LASTEXITCODE
```

结果：退出码 0。仓库未配置专用 lint/vet 命令，此处为语法验证。

## 未验证边界

以下均为**待隔离环境验证**：

- 并发核销：待隔离环境验证。
- JWT 撤销：待隔离环境验证。
- 订单状态竞争：待隔离环境验证。
- MySQL/Redis 双连接：待隔离环境验证。
- 退款“外部成功本地失败”：待隔离环境验证。
- 真实微信审核、短信、支付/退款及回调：待隔离环境验证。

## 安全与运维声明

- 未部署生产。
- 未进行生产故障注入。
- 未发送真实短信。
- 未发生支付或退款。
- 未提交密钥、证书或真实用户/订单数据。

## 回滚

回滚本 PR 的止血逻辑：`git revert bc428ff`。该回滚只恢复本次 commit，不应回退到绕过安全校验的其他历史版本。
