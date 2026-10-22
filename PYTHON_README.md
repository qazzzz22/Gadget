# Codex 本地代理修复工具 · Python v3.0.0

[下载 Python 版 ZIP](https://github.com/qazzzz22/Gadget/raw/refs/heads/main/downloads/Codex-Proxy-Repair-Python-v3.0.0.zip) · [SHA-256](https://github.com/qazzzz22/Gadget/blob/main/downloads/Codex-Proxy-Repair-Python-v3.0.0.zip.sha256)

Windows 10/11 本地 HTTP/Mixed 代理诊断与修复。核心、备份、还原、网络探测和打包均用 Python 编写，**不调用 PowerShell，不依赖 curl 或第三方 Python 包**。MIT 开源，完整源码可审阅。

## 使用

1. 完整解压 ZIP 到桌面等可写目录，先打开代理软件。
2. 双击 **Python-一键修复.cmd**。
3. 看到修复成功或配置已匹配后，保存工作，**完全退出 Codex（包括托盘）**，再从原图标打开并发一条消息验证。

需要 **Python 3.11 或更新版本**。启动器先检查 `py -3` 和 PATH 上的 Python，再检查现有 Codex 标准依赖目录及常见的用户 Python 安装目录；如果都不可用，会明确提示安装 Python，并且不改配置。不会自动安装软件或下载运行时。也可自行从 [python.org](https://www.python.org/downloads/windows/) 安装 Python。

`run-python.cmd` 只负责寻找 Python、传递参数和保留输出窗口，所有修复逻辑均在 `codex_proxy_repair.py`。无需管理员权限，请以平时使用 Codex 的 Windows 用户运行。

| 入口 | 作用 |
| --- | --- |
| `Python-一键修复.cmd` | 检测可用代理并修复当前用户配置 |
| `Python-仅诊断.cmd` | 只检查网络和修改计划，不改用户环境或 Codex 配置 |
| `Python-还原.cmd` | 还原最近一次 Python 版修复备份 |

也可以在终端直接运行：

```text
python codex_proxy_repair.py --mode diagnose
python codex_proxy_repair.py --mode repair
python codex_proxy_repair.py --mode repair --proxy-url http://127.0.0.1:12345
python codex_proxy_repair.py --mode restore
python codex_proxy_repair.py --mode restore --backup-directory "python-backups/某次备份目录"
```

如果使用 Windows Python Launcher，可把上述 `python` 换成 `py -3`。

## 检测与修改范围

- 从用户、进程和机器代理变量、现有 Codex `.env`、部分 Clash 配置、已开启的系统代理、常见代理进程监听端口和常用端口中发现候选；也可手动指定任意本机 HTTP/Mixed 端口。
- 通过 Python 标准库直接连接候选代理，建立 **HTTPS CONNECT 隧道并验证 TLS 证书**，向 Codex 服务发无凭据 GET。此探测不受失效的当前进程代理变量或 `NO_PROXY` 干扰。
- 只有可用线路通过后，才计划更新当前用户的 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY`。纯 SOCKS 端口只有在实际也支持 HTTP CONNECT 时才能通过检测。
- 更新现有 `.env` 中的代理行，包括小写键；保留注释和其他行，不创建新的 `.env`，不改 `.env.txt`。
- 清理会使 OpenAI/ChatGPT 请求绕过代理的 `NO_PROXY` 条目，保留其他排除项，保留或补齐本地绕过。
- 用 `tomllib` 完整解析并验证 TOML，只向已有 `shell_environment_policy.include_only` 补充缺少的 Windows 标准变量和代理变量；不创建新的筛选策略。解析失败、`inherit="none"`、排除规则冲突或无法安全定位时，不写入任何修复。

**用户代理环境变量也会影响其他新启动且遵循这些变量的程序**。已有远程或认证代理默认不覆盖，只有显式提供 `--proxy-url` 时才允许替换。不会改机器级变量、系统代理、WinHTTP、Clash 配置、快捷方式、开机启动、防火墙或证书信任。不会读取 `auth.json`，也不会上传配置、日志或聊天内容。

## 备份、原子写入与还原

有实际修改时，先在 `python-backups` 下保存原注册表值及其类型、原配置字节和校验值。每个备份目录使用 Windows ACL，只向当前用户、SYSTEM 和本机管理员授权。

临时文件在写入内容前先设置为私有，写入并刷新后再原子替换；在 Windows 使用 `ReplaceFileW` 保留已有配置的访问控制条目和相关元数据。保留 UTF-8（含或不含 BOM）、UTF-16 LE/BE 编码；不支持的编码会停止处理。

写入前和还原前会检查原状态，避免覆盖后续修改。可捕获的写入异常或 Ctrl+C 会尝试回滚本次仍保持本工具写入值的项目。断电、强制结束进程或磁盘/权限异常无法保证自动恢复；这时应保留备份，按校验结果手工恢复。状态为 `prepared` 且当前项目完整匹配修复后值时，也可显式指定该目录还原。

Python 版与 PowerShell 版的备份格式及目录独立，不能交叉还原。PowerShell 版备份继续用旧版入口恢复。

**备份可能包含 `.env` 的其他私密内容，不能转发已运行目录。** 传播时直接转发最初的 ZIP。打包采用明确的文件清单，不包含任何日志、备份或个人配置。日志位于 `python-logs`；远程/认证代理内容隐藏，分享日志前仍请检查本机路径。

## 检测边界

- 没有可用本机 HTTP/Mixed 代理时不写入，不会擅自清空代理或切换直连。
- 证书错误、TLS 错误、超时、HTTP 403/407/429 等不会判为成功，也不会绕过证书验证。
- 无凭据探测收到 401/405 或正常 HTTP 状态，只表示 CONNECT/TLS 和服务端响应通过；**不代表已验证登录、WebSocket 或完整流式聊天**。
- 代理软件需要保持运行。若端口再次变化，可以重新运行；若节点故障、登录失效、自定义模型中转未启动或有系统/组织网络策略冲突，需要进一步排查。
- 修复后已有 Codex 进程不会自动获得新环境；需要完全退出并重开，必要时注销并重新登录 Windows。

## 开发与验证

Python 3.11+，只有标准库：

```text
python -m unittest discover -s tests -p "test_python_repair.py" -v
python tools/build_python_release.py
```

测试使用模拟环境变量和临时文件；Windows 注册表集成测试仅创建独立的测试子键，不写真实的用户 `Environment`。真实代理验证使用 `--mode diagnose`，不改现有网络设置。

本版已在 Windows、Python 3.12.14 上通过 **54 项自动化测试**，包括真实本机 CONNECT 拒绝/TLS 失败检测、配置编码、注释和 TOML 校验、写入异常与取消回滚、后续改动保护、原文件访问权限、私有临时文件、启动器以及可重复打包。实机通过现有 HTTP 代理收到 Codex 无凭据 GET 的 HTTP 405，且诊断前后的真实用户变量和 Codex 配置保持不变。

发布包位于 `dist`，文件名为 `Codex-Proxy-Repair-Python-v3.0.0.zip`，同时生成 `.sha256`。重复打包需要加 `--force`。ZIP 内不包含 PowerShell 文件。旧版 PowerShell 工具和下载包继续保留。

本项目与 OpenAI 及各代理软件项目无隶属关系。[MIT License](LICENSE)。
