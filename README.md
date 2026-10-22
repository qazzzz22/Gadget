# Codex 本地代理一键修复工具

Windows local proxy diagnosis and repair for Codex. Open source under the [MIT License](LICENSE).

**推荐：[下载 Python v3.0.0 一键修复 ZIP](https://github.com/qazzzz22/Gadget/raw/refs/heads/main/downloads/Codex-Proxy-Repair-Python-v3.0.0.zip)** · [Python 版完整说明](PYTHON_README.md) · [SHA-256](https://github.com/qazzzz22/Gadget/blob/main/downloads/Codex-Proxy-Repair-Python-v3.0.0.zip.sha256)

Python 版需要 Python 3.11+，仅使用标准库，不调用 PowerShell 或 curl。解压后运行 **Python-一键修复.cmd**；也提供仅诊断和还原入口。包含 TOML 完整解析校验、原子写入、备份和后续修改保护。

源码为 [`codex_proxy_repair.py`](codex_proxy_repair.py)，测试及打包命令见 [Python 版说明](PYTHON_README.md)。

旧版保留：[下载 PowerShell v2.0.0 ZIP](https://github.com/qazzzz22/Gadget/raw/refs/heads/main/downloads/Codex-Proxy-Repair-v2.0.0.zip)。**以下为 PowerShell v2.0.0 使用说明**，Python 版请使用上面的专用入口和说明。

适用于 Windows 10/11 上 Codex 反复出现 `os error 10061`、连接被拒绝、`stream disconnected`、不断重连，并且原因是本地代理配置失效的情况。

这是可查看源码的个人排障工具，不是 OpenAI 官方软件。它不能保证修复所有网络错误。

## 一键使用

1. 右键 ZIP → **全部解压**，放到桌面等可写目录。不要在 ZIP 内直接运行。
2. 打开 Clash Verge、Clash、v2rayN 等代理软件，确认代理节点能联网。
3. 双击 **一键修复.cmd**，等待检测和修复结果。普通用户运行即可，不要以其他管理员账号运行。
4. 出现“修复已写入并校验”或“当前持久配置已匹配可用代理”后，保存工作，**完全退出 Codex，包括托盘**，再从原来的图标打开。
5. 发送一条简短消息，验证登录和流式聊天。如果仍缓存旧环境，注销并重新登录 Windows。

以后正常启动 Codex 即可，无需通过本工具启动。代理软件仍需运行；代理端口变化后可以重新运行修复。

首次探测通常需要数秒；节点不可用或候选端口较多时可能更久。不会自动结束任何正在进行的聊天。

## 能识别和修复什么

- 代理实际端口改变，而 Windows 用户 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY` 仍指向旧端口。
- 代理变量缺失，默认启动的 Codex 无法继承本地 HTTP 代理。
- 现有 Codex `.env` 中的本地代理变量陈旧，包括大小写形式；只改代理相关行。
- 用户或 Codex `.env` 的 `NO_PROXY` 中有 `*` 或 OpenAI/ChatGPT 域名，使请求绕过代理。修复时保留其他绕过条目，并补齐本地地址。
- Codex 自定义 `shell_environment_policy.include_only` 漏掉 Windows 必需环境变量或代理变量。

自动从当前进程/用户/系统环境、部分 Clash 配置、已开启的 Windows 系统代理、常见代理程序的监听端口，以及常用端口中寻找本机 HTTP/Mixed 代理。没有写死用户名、Codex 安装路径或代理端口。

每个候选先检查 TCP，再用系统 curl 验证 HTTPS CONNECT、TLS 证书和 Codex 服务端响应。只有通过后才生成修改计划，完整备份后写入。HTTPS 目标的代理地址通常仍为 `http://127.0.0.1:端口`。

## 三个入口

| 文件 | 用途 |
| --- | --- |
| `一键修复.cmd` | 自动检测并修复当前 Windows 用户配置 |
| `仅诊断.cmd` | 只检查和显示计划，不改环境变量或 Codex 配置；会生成日志 |
| `还原上次修复.cmd` | 还原最近一次尚未还原的完整修复备份 |
| `Fix-CodexNetwork.ps1` | 可查看、审阅的实际脚本源码 |

## 修改范围

修复会修改当前用户的四个代理环境变量：`HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY`。**其他新启动且使用这些变量的程序也会受到影响**；这是修复默认启动继承环境的方式。已经运行的程序需要重开。

如果存在 Codex 的 `.env`，更新其中已有的代理行；不会新建 `.env`，也不会改动其中其他设置。如果 `config.toml` 含自定义命令环境白名单，会补齐 Windows 标准变量和代理变量；没有白名单时不主动创建它。

Codex 用户目录通过 `CODEX_HOME` 或当前用户的 `.codex` 自动确定。保留文件编码和其他配置内容。

不会改系统代理、WinHTTP、Clash 配置、快捷方式、开机启动、防火墙、证书信任或系统执行策略。不会读取 Codex `auth.json`，不会发送聊天内容、登录凭据，也不会下载或执行远程脚本。探测只向 `chatgpt.com` 发送无凭据请求。

## 备份与还原

每次有实际修改时，在本工具的 `backups` 下生成独立备份，保存修改前环境变量、原始配置文件和校验值。修复失败会尝试回滚已经写入的项目。

双击 `还原上次修复.cmd` 可还原最近一次修复。若设置在修复后又被其他程序或用户更改，工具会停止还原，避免覆盖后续修改；这时需要根据备份手工合并。

备份目录仅授权当前用户、SYSTEM 和本机管理员访问。备份可能包含原 `.env` 中的私密内容，**不要把已运行目录的 backups 发给别人**。诊断日志不展示远程代理地址或代理密码，但可能包含本机路径，分享前仍请检查。

传播时请直接转发最初下载的 ZIP，或只复制本说明和四个脚本文件。不要打包 `backups`、`logs` 或个人配置。

## 自动检测不到端口

在解压目录打开 PowerShell，例如代理 HTTP/Mixed 端口为 12345：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Fix-CodexNetwork.ps1 -Mode Repair -ProxyUrl http://127.0.0.1:12345
```

只诊断：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Fix-CodexNetwork.ps1 -Mode Diagnose
```

还原指定备份：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Fix-CodexNetwork.ps1 -Mode Restore -BackupDirectory '.\backups\备份文件夹名'
```

`ExecutionPolicy Bypass` 仅作用于这次 PowerShell 进程，不改变系统执行策略。组织策略、应用控制或下载文件拦截可能仍会阻止脚本；请遵守设备策略。

## 不会自动处理的情况

| 检测结果 | 处理方式 |
| --- | --- |
| 所有端口未监听 | 先启动代理软件，确认 HTTP/Mixed 端口。纯 SOCKS 端口不能当作 HTTP 端口 |
| CONNECT/TLS 失败、超时 | 检查节点、规则和网络；工具保留原配置 |
| HTTP 403、407、429 或证书错误 | 不自动选用该线路，也不会关闭安全检查；更换可用节点或检查代理 |
| 已有远程或认证代理 | 默认不覆盖；确认需要改用本地代理后，显式使用 `-ProxyUrl` |
| 自定义 `inherit="none"` 或复杂 TOML | 保留自定义策略，停止自动修改，请手动检查 |
| 系统级代理变量、PAC、TUN 路由或系统策略冲突 | 日志仅辅助定位，工具不调整系统级设置 |
| 自定义模型中转服务没有启动 | 本工具不修改 provider、base_url 或服务配置 |
| 登录失效、服务故障、节点阻断 WebSocket/流式连接 | 普通 HTTPS 探测不能证明完整聊天恢复，需要在 Codex 中发消息验证 |
| 不使用本地代理的直连环境 | 本版专门修复本地 HTTP/Mixed 代理，不会擅自清空代理或切换直连 |

## 版本和验证

v2.0.0，2026-10-22。需要 Windows PowerShell 5.1 或 PowerShell 7，以及系统自带 curl.exe，无额外依赖。

Windows PowerShell 5.1 和 PowerShell 7 均通过 57 项隔离检查，覆盖地址校验、绕过规则、配置编码、备份还原、写入失败回滚、重复运行和后续修改保护。测试只操作模拟环境和临时文件。已在制作电脑验证真实可用代理和仅诊断模式。不同代理软件、组织网络和设备仍需按日志及实际聊天结果验证。

## 开发与打包

在仓库根目录运行隔离检查，不会更改真实用户代理：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-PortableRepair.ps1
```

生成只含工具、说明和许可证的发布 ZIP，以及 SHA-256 校验文件：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tools\Build-Release.ps1
```

产物位于 `dist`。打包脚本使用明确的文件清单，不会打包运行日志、备份、测试临时文件或个人配置。请使用发布包分发给普通用户；也可下载完整源码并直接运行根目录中的入口脚本。

提交问题时请提供 Windows 和 PowerShell 版本、代理软件名称及端口、错误文本和脱敏后的诊断结果。请勿上传 `.env`、`auth.json`、备份、代理密码或完整个人配置。

欢迎提交问题和 Pull Request。修改修复逻辑时，请补充能够复现问题的隔离检查，并保留写入前验证、备份和失败回滚行为。

## 许可证

[MIT License](LICENSE)。本项目与 OpenAI 及各代理软件项目无隶属关系。
