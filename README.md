# KiraAI Error Notifier

将 KiraAI 的异常事件或 ERROR/CRITICAL 日志，通过指定的 KiraAI 适配器直接发送到主人会话。

## 两种模式

- `on_exception`：监听 KiraAI 的 `ON_EXCEPTION`。覆盖框架上报的插件、模型/API 和工具执行异常，噪声较少。
- `all_error`：为 KiraAI 创建的日志记录器安装 `ERROR` 级监听器。覆盖面更大，也更容易产生重复错误，因此必须配合冷却和每小时上限。

两种模式互斥，由 WebUI 配置选择。插件不会修改 KiraAI 核心文件。

## 目标会话

`target_session` 格式为：

```text
适配器实例名:dm|gm:会话ID
```

例如：

```text
qq:dm:123456789
```

这里的第一段必须是 KiraAI 当前实际配置的适配器实例名。

## 安全措施

- 默认关闭，目标会话为空时不会启动监听。
- 相同错误按指纹去重并冷却。
- 所有错误共享每小时发送上限。
- 默认不发送完整调用栈。
- 自动遮盖常见 token、密钥、密码、Bearer 凭据、URL 敏感参数和长数字 ID。
- 插件自己的发送错误不会再次触发通知。

## 限制

`all_error` 监听的是 KiraAI Python 日志系统，不包括 NapCat Docker 日志、systemd 日志或整台服务器宕机。若 NapCat/QQ 适配器已经不可用，也无法再通过该适配器发送提醒；这类故障需要 ntfy 等独立渠道监控。

