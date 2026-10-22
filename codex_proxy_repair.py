#!/usr/bin/env python3
"""Windows Codex proxy repair, Python edition. Python 3.11+, standard library only.

Importing this module does not access the registry, network, or configuration.
"""
from __future__ import annotations

import argparse
import codecs
import csv
import ctypes
import fnmatch
import functools
import hashlib
import http.client
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import tomllib
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime
from urllib.parse import urlsplit

VERSION = "3.0.0"
KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")
REQUIRED = ("SystemRoot", "windir", "SystemDrive", "ComSpec", "PATHEXT", "OS",
            "LOCALAPPDATA", "APPDATA", *KEYS)
HOSTS = ("chatgpt.com", "api.openai.com", "auth.openai.com", "ws.chatgpt.com")
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class RepairError(Exception):
    """An actionable error whose message never contains proxy credentials."""


def loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def proxy_parts(value: str):
    text = value.strip()
    if re.search(r'[\s"<>|&\\?#]', text):
        raise ValueError("unsupported proxy")
    parsed = urlsplit(text if "://" in text else "http://" + text)
    if (not loopback(parsed.hostname) or parsed.username is not None
            or parsed.password is not None or parsed.path not in ("", "/")):
        raise ValueError("unsupported proxy")
    port = parsed.port if parsed.port is not None else 80
    if not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return parsed, port


def normalize_proxy(value: str | None, *, mixed_candidate: bool = False) -> str | None:
    if not value:
        return None
    try:
        parsed, port = proxy_parts(value)
        schemes = ("http", "socks4", "socks5", "socks5h") if mixed_candidate else ("http",)
        if parsed.scheme not in schemes:
            return None
        host = parsed.hostname.lower()
        if ":" in host:
            host = f"[{host}]"
        return f"http://{host}:{port}"
    except (ValueError, TypeError):
        return None


def local_setting(value: str | None) -> bool:
    return not value or normalize_proxy(value, mixed_candidate=True) is not None


def safe_label(value: str | None) -> str:
    if not value:
        return "(未设置)"
    proxy = normalize_proxy(value, mixed_candidate=True)
    return proxy or "(远程、认证或无法识别的配置，内容已隐藏)"


def repair_no_proxy(value: str | None) -> str:
    kept: list[str] = []
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        domain = item.lower().lstrip(".")
        if domain.count(":") == 1 and domain.rsplit(":", 1)[1].isdigit():
            domain = domain.rsplit(":", 1)[0]
        bypasses = domain == "*" or any(
            host == domain or host.endswith("." + domain) or fnmatch.fnmatchcase(host, domain)
            for host in HOSTS
        )
        if not bypasses and item.lower() not in [v.lower() for v in kept]:
            kept.append(item)
    for local in ("localhost", "127.0.0.1", "::1"):
        if local not in [v.lower() for v in kept]:
            kept.append(local)
    return ",".join(kept)


@dataclass(frozen=True)
class Document:
    data: bytes
    text: str
    encoding: str
    bom: bytes

    @classmethod
    def decode(cls, data: bytes) -> Document:
        if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
            raise RepairError("不支持 UTF-32 配置，未改写文件。请转换为 UTF-8 后重试。")
        for bom, encoding in ((codecs.BOM_UTF8, "utf-8"),
                              (codecs.BOM_UTF16_LE, "utf-16-le"),
                              (codecs.BOM_UTF16_BE, "utf-16-be")):
            if data.startswith(bom):
                return cls(data, data[len(bom):].decode(encoding), encoding, bom)
        return cls(data, data.decode("utf-8"), "utf-8", b"")

    def encode(self, text: str) -> bytes:
        return self.bom + text.encode(self.encoding)


def array_end(text: str, start: int) -> tuple[int, str]:
    """Find a TOML array's closing bracket, respecting strings and comments."""
    depth, i, last = 0, start, ""
    while i < len(text):
        c = text[i]
        if c == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end + 1
            continue
        if c in "\"'":
            quote = c * (3 if text.startswith(c * 3, i) else 1)
            i += len(quote)
            while i < len(text):
                if text.startswith(quote, i):
                    i += len(quote)
                    break
                if c == '"' and text[i] == "\\":
                    i += 2
                else:
                    i += 1
            last = c
            continue
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return i, last
        if not c.isspace():
            last = c
        i += 1
    raise RepairError("无法定位 TOML 数组末尾，未改写配置。")


def update_allowlist(text: str) -> str:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise RepairError("config.toml 不是有效 TOML，未修改任何配置。") from exc
    policy = data.get("shell_environment_policy")
    if policy is None:
        return text
    if not isinstance(policy, dict):
        raise RepairError("shell_environment_policy 格式不受支持。")
    if policy.get("inherit") == "none":
        raise RepairError('自定义 inherit="none" 策略需要手工检查，未自动覆盖。')
    include = policy.get("include_only")
    if include is None:
        return text
    exclude = policy.get("exclude", [])
    for values in (include, exclude):
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise RepairError("Codex 环境变量筛选列表格式不正确。")
    if any(fnmatch.fnmatchcase(key.lower(), pattern.lower()) for key in REQUIRED for pattern in exclude):
        raise RepairError("exclude 策略排除了必要变量，未自动改写自定义策略。")
    missing = [key for key in REQUIRED if not any(
        fnmatch.fnmatchcase(key.lower(), pattern.lower()) for pattern in include
    )]
    if not missing:
        return text
    header = re.search(r'(?m)^[ \t]*\[[ \t]*(?:shell_environment_policy|"shell_environment_policy"|\'shell_environment_policy\')[ \t]*\][ \t]*(?:#[^\r\n]*)?\r?$', text)
    if not header:
        raise RepairError("环境策略使用内联或特殊 TOML 写法，未自动改写。")
    # Limit the search to this table, rather than a similarly named key elsewhere.
    next_header = re.search(r"(?m)^[ \t]*\[", text[header.end():])
    stop = header.end() + next_header.start() if next_header else len(text)
    match = re.search(r'(?m)^[ \t]*(?:include_only|"include_only"|\'include_only\')[ \t]*=[ \t]*\[', text[header.end():stop])
    if not match:
        raise RepairError("无法安全定位 include_only 数组，未改写配置。")
    start = header.end() + match.end() - 1
    end, last = array_end(text, start)
    newline = "\r\n" if "\r\n" in text else "\n"
    comma = "," if include and last != "," else ""
    addition = newline + comma + ",".join(json.dumps(key) for key in missing) + newline
    result = text[:end] + addition + text[end:]
    expected = dict(data)
    expected["shell_environment_policy"] = dict(policy, include_only=include + missing)
    if tomllib.loads(result) != expected:
        raise RepairError("TOML 改写校验失败，未保存文件。")
    return result


@dataclass(frozen=True)
class EnvEntry:
    key: str
    value: str
    start: int
    end: int
    prefix: str
    suffix: str
    quote: str


def quoted_end(value: str, quote: str) -> int | None:
    i = 1
    while i < len(value):
        if value[i] == quote:
            return i
        i += 2 if quote == '"' and value[i] == "\\" else 1
    return None


def dotenv_entries(text: str) -> list[EnvEntry]:
    entries: list[EnvEntry] = []
    offset, multiline = 0, ""
    for line in text.splitlines(keepends=True):
        raw = line.rstrip("\r\n")
        if multiline:
            if quoted_end(multiline + raw, multiline) is not None:
                multiline = ""
            offset += len(line)
            continue
        match = re.match(r"([ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z_0-9]*)[ \t]*=[ \t]*)(.*)", raw)
        if not match:
            offset += len(line)
            continue
        prefix, key, rest = match.groups()
        quote = rest[:1] if rest[:1] in ("'", '"') else ""
        if quote:
            end = quoted_end(rest, quote)
            if end is None:
                if key.upper() in KEYS:
                    raise RepairError(".env 中的代理变量跨行或引号未闭合，未改写文件。")
                multiline = quote
                offset += len(line)
                continue
            value, suffix = rest[1:end], rest[end + 1:]
            if suffix.strip() and not suffix.lstrip().startswith("#"):
                if key.upper() in KEYS:
                    raise RepairError(".env 代理行格式不明确，未改写文件。")
        else:
            part = re.match(r"(.*?)([ \t]+#.*)?$", rest)
            value, suffix = part.group(1).rstrip(), part.group(2) or ""
        if key.upper() in KEYS:
            entries.append(EnvEntry(key, value, offset, offset + len(raw), prefix, suffix, quote))
        offset += len(line)
    return entries


def update_dotenv(text: str, address: str, explicit: bool) -> str:
    result = text
    for entry in reversed(dotenv_entries(text)):
        if entry.key.upper() == "NO_PROXY":
            value = repair_no_proxy(entry.value)
        else:
            if not explicit and not local_setting(entry.value):
                raise RepairError(".env 有远程或认证代理；仅在 --proxy-url 显式指定时覆盖。")
            value = address
        line = entry.prefix + entry.quote + value + entry.quote + entry.suffix
        result = result[:entry.start] + line + result[entry.end:]
    return result


@dataclass(frozen=True)
class RegistryValue:
    value: str | None = None
    kind: int = 1


class WindowsRegistry:
    def __init__(self, user_key: str = "Environment"):
        if os.name != "nt":
            raise RepairError("修复和还原功能仅支持 Windows 10/11。")
        import winreg
        self.reg = winreg
        self.user_key = user_key

    def get(self, key: str) -> RegistryValue:
        try:
            with self.reg.OpenKey(self.reg.HKEY_CURRENT_USER, self.user_key) as handle:
                value, kind = self.reg.QueryValueEx(handle, key)
        except FileNotFoundError:
            return RegistryValue()
        if kind not in (self.reg.REG_SZ, self.reg.REG_EXPAND_SZ) or not isinstance(value, str):
            raise RepairError("用户代理变量的注册表类型不受支持，未改写。")
        return RegistryValue(value, kind)

    def set(self, key: str, value: RegistryValue) -> None:
        if key not in KEYS:
            raise RepairError("拒绝写入代理变量以外的注册表项。")
        with self.reg.CreateKeyEx(self.reg.HKEY_CURRENT_USER, self.user_key, 0, self.reg.KEY_SET_VALUE) as handle:
            if value.value is None:
                try:
                    self.reg.DeleteValue(handle, key)
                except FileNotFoundError:
                    pass
            else:
                self.reg.SetValueEx(handle, key, 0, value.kind, value.value)

    def machine(self, key: str) -> str | None:
        try:
            with self.reg.OpenKey(self.reg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment") as handle:
                value, kind = self.reg.QueryValueEx(handle, key)
                return value if kind in (1, 2) and isinstance(value, str) else None
        except FileNotFoundError:
            return None

    def system_proxy(self) -> str | None:
        try:
            with self.reg.OpenKey(self.reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as handle:
                if self.reg.QueryValueEx(handle, "ProxyEnable")[0]:
                    return self.reg.QueryValueEx(handle, "ProxyServer")[0]
        except FileNotFoundError:
            pass
        return None

    def codex_home(self) -> Path:
        try:
            with self.reg.OpenKey(self.reg.HKEY_CURRENT_USER, "Environment") as handle:
                value = self.reg.QueryValueEx(handle, "CODEX_HOME")[0]
        except FileNotFoundError:
            value = os.environ.get("CODEX_HOME")
        return Path(os.path.expandvars(value)).resolve() if value else (Path.home() / ".codex").resolve()


def windows_binary(name: str) -> Path:
    root = os.environ.get("SystemRoot") or os.environ.get("windir")
    if not root and os.name == "nt":
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion") as handle:
            root = winreg.QueryValueEx(handle, "SystemRoot")[0]
    if not root:
        raise RepairError("无法确定 Windows 安装目录。")
    return Path(root) / "System32" / name


@functools.lru_cache(maxsize=1)
def identity() -> str:
    if os.name != "nt":
        return str(os.getuid())
    result = subprocess.run([str(windows_binary("whoami.exe")), "/user", "/fo", "csv", "/nh"],
                            capture_output=True, timeout=5, check=True, creationflags=CREATE_NO_WINDOW)
    match = re.search(rb"S-1-\d+(?:-\d+)+", result.stdout)
    if not match:
        raise RepairError("无法识别当前 Windows 用户，未写入配置。")
    return match.group().decode("ascii")


def private_directory(path: Path) -> None:
    if os.name != "nt":
        path.mkdir(mode=0o700)
        return
    from ctypes import wintypes
    class SecurityAttributes(ctypes.Structure):
        _fields_ = [("nLength", wintypes.DWORD), ("lpSecurityDescriptor", ctypes.c_void_p),
                    ("bInheritHandle", wintypes.BOOL)]
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    kernel.CreateDirectoryW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(SecurityAttributes)]
    kernel.CreateDirectoryW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    sddl = f"D:P(A;OICI;FA;;;{identity()})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    if not convert(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        attrs = SecurityAttributes(ctypes.sizeof(SecurityAttributes), descriptor.value, False)
        if not kernel.CreateDirectoryW(str(path), ctypes.byref(attrs)):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def private_file(path: Path) -> None:
    """Protect the empty staging file before any configuration bytes are written."""
    if os.name != "nt":
        os.chmod(path, 0o600)
        return
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    convert = advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p]
    convert.restype = wintypes.BOOL
    advapi.SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p]
    advapi.SetFileSecurityW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    descriptor = ctypes.c_void_p()
    if not convert(f"D:P(A;;FA;;;{identity()})(A;;FA;;;SY)(A;;FA;;;BA)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        if not advapi.SetFileSecurityW(str(path), 0x80000004, descriptor):
            raise ctypes.WinError(ctypes.get_last_error())
    finally:
        kernel.LocalFree(descriptor)


def checked_read(path: Path) -> bytes:
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink > 1
            or getattr(info, "st_file_attributes", 0) & 0x400):
        raise RepairError("配置或备份不是普通独立文件，拒绝自动写入。")
    return path.read_bytes()


def atomic_write(path: Path, data: bytes) -> None:
    if path.exists():
        checked_read(path)
    fd, name = tempfile.mkstemp(prefix=".codex-proxy-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            private_file(Path(name))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if os.name == "nt" and path.exists():
            # ReplaceFile preserves the target DACL, creation time and streams.
            # https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-replacefilew
            from ctypes import wintypes
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            replace = kernel.ReplaceFileW
            replace.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
                                wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
            replace.restype = wintypes.BOOL
            if not replace(str(path), name, None, 0, None, None):
                raise ctypes.WinError(ctypes.get_last_error())
        else:
            if path.exists():
                os.chmod(name, stat.S_IMODE(path.stat().st_mode))
            os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


@dataclass(frozen=True)
class VariableChange:
    key: str
    before: RegistryValue
    after: RegistryValue


@dataclass(frozen=True)
class FileChange:
    path: Path
    before: bytes
    after: bytes


@dataclass
class Plan:
    variables: list[VariableChange]
    files: list[FileChange]

    @property
    def empty(self) -> bool:
        return not self.variables and not self.files


def make_plan(registry, home: Path, address: str, explicit: bool = False) -> Plan:
    if normalize_proxy(address) != address:
        raise RepairError("无效的本机 HTTP/Mixed 代理地址。")
    variables, files = [], []
    for key in KEYS:
        before = registry.get(key)
        if key == "NO_PROXY":
            value = repair_no_proxy(before.value)
        else:
            if not explicit and not local_setting(before.value):
                raise RepairError("已有远程或认证用户代理，未覆盖；确认后可用 --proxy-url 显式指定。")
            value = address
        after = RegistryValue(value, before.kind)
        if before != after:
            variables.append(VariableChange(key, before, after))
    for name in ("config.toml", ".env"):
        path = home / name
        if not path.exists():
            continue
        doc = Document.decode(checked_read(path))
        text = update_allowlist(doc.text) if name == "config.toml" else update_dotenv(doc.text, address, explicit)
        after = doc.encode(text)
        if after != doc.data:
            files.append(FileChange(path, doc.data, after))
    return Plan(variables, files)


def preflight(plan: Plan, registry) -> None:
    for item in plan.variables:
        if item.key not in KEYS or registry.get(item.key) != item.before:
            raise RepairError("用户代理在计划生成后有变化，未继续写入。")
    for item in plan.files:
        if checked_read(item.path) != item.before:
            raise RepairError("配置在计划生成后有变化，未继续写入。")


def execute_changes(plan: Plan, registry) -> None:
    """Write a validated plan; on error undo only values still owned by this run."""
    preflight(plan, registry)
    variables, files = [], []
    try:
        for item in plan.variables:
            if registry.get(item.key) != item.before:
                raise RepairError("写入前用户代理被并发修改。")
            variables.append(item)
            registry.set(item.key, item.after)
            if registry.get(item.key) != item.after:
                raise RepairError("用户代理写入校验失败。")
        for item in plan.files:
            if checked_read(item.path) != item.before:
                raise RepairError("写入前配置被并发修改。")
            files.append(item)
            atomic_write(item.path, item.after)
            if checked_read(item.path) != item.after:
                raise RepairError("配置写入校验失败。")
    except BaseException as exc:
        failed = False
        for item in reversed(files):
            try:
                current = checked_read(item.path)
                if current == item.after:
                    atomic_write(item.path, item.before)
                elif current != item.before:
                    failed = True
            except Exception:
                failed = True
        for item in reversed(variables):
            try:
                current = registry.get(item.key)
                if current == item.after:
                    registry.set(item.key, item.before)
                elif current != item.before:
                    failed = True
            except Exception:
                failed = True
        if failed:
            raise RepairError("写入失败，部分项目无法回滚；请保留备份并手工检查。") from exc
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise RepairError("写入失败，已回滚本次修改。") from exc


def write_manifest(directory: Path, manifest: dict) -> None:
    atomic_write(directory / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"))


def apply_plan(plan: Plan, registry, tool_root: Path, home: Path) -> Path | None:
    if plan.empty:
        return None
    preflight(plan, registry)
    root = tool_root / "python-backups"
    root.mkdir(parents=True, exist_ok=True)
    directory = root / (datetime.now().strftime("%Y%m%d-%H%M%S-%f") + "-" + uuid.uuid4().hex[:8])
    private_directory(directory)
    records = []
    for i, item in enumerate(plan.files):
        name = f"file-{i}.before"
        atomic_write(directory / name, item.before)
        records.append(dict(path=str(item.path.resolve()), backup=name,
                            before_hash=digest(item.before), after_hash=digest(item.after)))
    manifest = dict(format="codex-proxy-repair-python", version=1, tool_version=VERSION,
                    owner=identity(), home=str(home.resolve()), state="prepared",
                    variables=[asdict(v) for v in plan.variables], files=records)
    write_manifest(directory, manifest)
    try:
        execute_changes(plan, registry)
    except BaseException:
        manifest["state"] = "interrupted"
        write_manifest(directory, manifest)
        raise
    manifest["state"] = "applied"
    try:
        write_manifest(directory, manifest)
    except Exception as exc:
        # The prepared backup remains usable for explicit recovery after a crash.
        raise RepairError(f"配置已写入，但备份状态保存失败。请保留备份目录：{directory}") from exc
    return directory


def registry_value(data: dict) -> RegistryValue:
    if not isinstance(data, dict) or set(data) != {"value", "kind"}:
        raise RepairError("备份中的注册表记录不正确。")
    if data["kind"] not in (1, 2) or (data["value"] is not None and not isinstance(data["value"], str)):
        raise RepairError("备份中的注册表值类型不正确。")
    return RegistryValue(**data)


def restore_backup(directory: Path, registry, home: Path) -> None:
    manifest = json.loads(checked_read(directory / "manifest.json").decode("utf-8"))
    if (manifest.get("format") != "codex-proxy-repair-python" or manifest.get("version") != 1
            or manifest.get("owner") != identity() or manifest.get("state") not in ("applied", "prepared")
            or Path(manifest.get("home", "")).resolve() != home.resolve()):
        raise RepairError("备份不完整、已还原，或不属于当前用户和 Codex 目录。")
    variables, files, seen = [], [], set()
    for item in manifest["variables"]:
        key = item["key"]
        if key not in KEYS or key in seen:
            raise RepairError("备份中包含不支持或重复的变量。")
        seen.add(key)
        variables.append(VariableChange(key, registry_value(item["after"]), registry_value(item["before"])))
    allowed = {(home / name).resolve() for name in ("config.toml", ".env")}
    seen_paths = set()
    for item in manifest["files"]:
        path = Path(item["path"])
        if path.resolve() not in allowed or path.resolve() in seen_paths or not re.fullmatch(r"file-\d+\.before", item["backup"]):
            raise RepairError("备份目标或文件名不正确，未还原。")
        seen_paths.add(path.resolve())
        old = checked_read(directory / item["backup"])
        current = checked_read(path)
        if digest(old) != item["before_hash"] or digest(current) != item["after_hash"]:
            raise RepairError("配置或备份在修复后有变化，停止还原以保留后续修改。")
        files.append(FileChange(path, current, old))
    execute_changes(Plan(variables, files), registry)
    manifest["state"] = "restored"
    try:
        write_manifest(directory, manifest)
    except OSError as exc:
        raise RepairError("配置已还原，但备份状态保存失败；请保留备份，不要重复还原。") from exc


def latest_backup(tool_root: Path) -> Path:
    root = tool_root / "python-backups"
    for directory in sorted(root.glob("*/manifest.json"), reverse=True):
        try:
            manifest = json.loads(checked_read(directory).decode("utf-8"))
            if manifest.get("format") == "codex-proxy-repair-python" and manifest.get("state") == "applied":
                return directory.parent
        except (OSError, ValueError, RepairError):
            continue
    raise RepairError("没有可还原的 Python 版修复备份；PowerShell 版备份请用原入口还原。")


@dataclass(frozen=True)
class Probe:
    status: int = 0
    error: str = ""

    @property
    def usable(self) -> bool:
        return not self.error and (200 <= self.status < 400 or self.status in (401, 405))


def probe_proxy(address: str, timeout: float = 8) -> Probe:
    normalized = normalize_proxy(address)
    if not normalized:
        return Probe(error="invalid_proxy")
    parsed = urlsplit(normalized)
    conn = http.client.HTTPSConnection(parsed.hostname, parsed.port, timeout=timeout,
                                       context=ssl.create_default_context())
    conn.set_tunnel("chatgpt.com", 443)
    try:
        conn.request("GET", "/backend-api/codex/responses", headers={"User-Agent": f"CodexProxyRepairPython/{VERSION}"})
        return Probe(status=conn.getresponse().status)
    except ssl.SSLCertVerificationError:
        return Probe(error="certificate")
    except ssl.SSLError:
        return Probe(error="tls")
    except (TimeoutError, socket.timeout):
        return Probe(error="timeout")
    except OSError as exc:
        # Never include the exception text in logs; it may contain proxy details.
        return Probe(error="proxy_auth" if "407" in str(exc) else "connection")
    except http.client.HTTPException:
        return Probe(error="protocol")
    finally:
        conn.close()


def port_open(address: str) -> bool:
    parsed = urlsplit(address)
    try:
        with socket.create_connection((parsed.hostname, parsed.port), timeout=0.5):
            return True
    except OSError:
        return False


def process_ports() -> list[str]:
    """Optional discovery for uncommon ports; no PowerShell/WMI dependency."""
    try:
        process = subprocess.run([str(windows_binary("tasklist.exe")), "/fo", "csv", "/nh"],
                                 capture_output=True, timeout=5, check=True, creationflags=CREATE_NO_WINDOW)
        rows = csv.reader(io.StringIO(process.stdout.decode(errors="replace")))
        ids = {row[1] for row in rows if len(row) > 1 and re.fullmatch(
            r"(?:mihomo.*|clash.*|sing-box|xray|v2ray|v2rayN|nekoray|hiddify.*)\.exe", row[0], re.I)}
        if not ids:
            return []
        result = subprocess.run([str(windows_binary("netstat.exe")), "-ano", "-p", "tcp"],
                                capture_output=True, timeout=5, check=True, creationflags=CREATE_NO_WINDOW)
        found = []
        for line in result.stdout.decode(errors="replace").splitlines():
            columns = line.split()
            if len(columns) != 5 or columns[0].upper() != "TCP" or columns[-1] not in ids or not columns[2].endswith(":0"):
                continue
            host, port = columns[1].rsplit(":", 1)
            if host in ("0.0.0.0", "127.0.0.1", "[::]", "[::1]") and port.isdigit():
                found.append(f"http://{'[::1]' if host == '[::1]' else '127.0.0.1'}:{port}")
        return found
    except (OSError, subprocess.SubprocessError, RepairError):
        return []


def candidates(registry, home: Path, explicit: str | None = None, roaming: Path | None = None) -> list[str]:
    if explicit:
        proxy = normalize_proxy(explicit)
        if not proxy:
            raise RepairError("--proxy-url 只支持无认证的本机 HTTP/Mixed 代理，例如 http://127.0.0.1:7897。")
        return [proxy]
    values = []
    for getter in (lambda key: registry.get(key).value, os.environ.get, registry.machine):
        values.extend(getter(key) for key in KEYS[:3])
    dot_env = home / ".env"
    if dot_env.exists():
        values.extend(e.value for e in dotenv_entries(Document.decode(checked_read(dot_env)).text) if e.key.upper() != "NO_PROXY")
    roaming = roaming or Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming")))
    for relative in ("io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml",
                     "io.github.clash-verge-rev.clash-verge-rev/verge.yaml",
                     "clash-verge/clash-verge.yaml", "clash/config.yaml", "clash_win/config.yaml"):
        path = roaming / relative
        if path.is_file():
            for port in re.findall(r"(?m)^(?:mixed-port|port|verge_mixed_port|verge_port):[ \t]*(\d{1,5})[ \t]*(?:#[^\r\n]*)?\r?$",
                                   path.read_text(encoding="utf-8-sig")):
                values.append("http://127.0.0.1:" + port)
    system = registry.system_proxy()
    if system:
        values.extend(re.sub(r"^(?:http|https)=", "", entry) for entry in system.split(";"))
    values.extend(process_ports())
    values.extend(f"http://127.0.0.1:{port}" for port in (7897, 7890, 7899, 10809, 2080, 20171, 17890, 8080, 1080))
    found = []
    for value in values:
        proxy = normalize_proxy(value, mixed_candidate=True)
        if proxy and proxy not in found:
            found.append(proxy)
    return found


def refresh_environment() -> bool:
    if os.name != "nt":
        return False
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    send = user32.SendMessageTimeoutW
    send.argtypes = [wintypes.HWND, wintypes.UINT, ctypes.c_size_t, wintypes.LPCWSTR,
                     wintypes.UINT, wintypes.UINT, ctypes.POINTER(ctypes.c_size_t)]
    send.restype = ctypes.c_ssize_t
    result = ctypes.c_size_t()
    return bool(send(0xFFFF, 0x1A, 0, "Environment", 2, 500, ctypes.byref(result)))


class Reporter:
    def __init__(self):
        self.lines: list[str] = []

    def __call__(self, message: str) -> None:
        self.lines.append(message)
        print(message, flush=True)

    def save(self, root: Path) -> None:
        try:
            path = root / "python-logs"
            path.mkdir(exist_ok=True)
            filename = datetime.now().strftime("%Y%m%d-%H%M%S-%f") + ".txt"
            (path / filename).write_text("\n".join(self.lines) + "\n", encoding="utf-8")
            print(f"诊断记录：{path / filename}")
        except OSError:
            print("无法保存日志，请完整解压到桌面等可写目录。")


def run(args, registry, root: Path, report: Reporter) -> None:
    home = registry.codex_home()
    report(f"Codex 本地代理修复工具 Python v{VERSION}；当前模式：{args.mode}")
    if args.mode == "restore":
        directory = Path(args.backup_directory).resolve() if args.backup_directory else latest_backup(root)
        restore_backup(directory, registry, home)
        report("已还原本次 Python 版备份。")
        if not refresh_environment():
            report("环境通知未全部成功，请注销后重新登录 Windows。")
        report("请完全退出并重开 Codex。")
        return
    for key in KEYS[:3]:
        report(f"用户 {key}: {safe_label(registry.get(key).value)}")
    if (home / ".env.txt").exists():
        report("发现 .env.txt；它不同于 .env，本工具不改写这个文件。")
    selected = None
    for proxy in candidates(registry, home, args.proxy_url):
        if not port_open(proxy):
            report(f"未监听或连接失败：{proxy}")
            continue
        report(f"验证 HTTP CONNECT / TLS：{proxy}")
        probe = probe_proxy(proxy, args.timeout)
        report(f"  HTTP={probe.status}，结果={probe.error or 'TLS 已验证'}")
        if probe.usable:
            selected = proxy
            break
    if selected is None:
        raise RepairError("未找到通过 HTTPS 验证的本机代理，未修改配置。请启动代理软件、检查节点或用 --proxy-url 指定端口。")
    plan = make_plan(registry, home, selected, bool(args.proxy_url))
    report(f"选定代理：{selected}；计划更新用户变量 {len(plan.variables)} 项，配置文件 {len(plan.files)} 个。")
    if args.mode == "diagnose":
        report("仅诊断完成，没有修改用户环境变量或 Codex 配置。")
        return
    backup = apply_plan(plan, registry, root, home)
    if backup:
        report(f"修复已写入并校验。私有备份：{backup}")
        report("正在通知 Windows 刷新环境……")
        if not refresh_environment():
            report("环境通知未全部成功，请注销后重新登录 Windows。")
    else:
        report("当前持久配置已匹配可用代理，无需重复修改。")
    report("保持代理软件运行，保存工作并完全退出 Codex（包括托盘），再从原图标打开。")
    report("HTTPS 探测不代表完整聊天恢复，重开后请发送一条消息验证登录和流式连接。")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Codex 本地 HTTP/Mixed 代理一键诊断、修复与还原（Python 3.11+）。")
    parser.add_argument("--mode", choices=("repair", "diagnose", "restore"), default="repair")
    parser.add_argument("--proxy-url", help="显式指定本机 HTTP/Mixed 代理，例如 http://127.0.0.1:7897")
    parser.add_argument("--timeout", type=float, default=8, help="网络操作超时秒数，范围 3–30")
    parser.add_argument("--backup-directory", help="还原指定的 Python 版备份目录")
    args = parser.parse_args(argv)
    if not 3 <= args.timeout <= 30:
        parser.error("--timeout 必须在 3–30 秒之间")
    report = Reporter()
    root = Path(__file__).resolve().parent
    try:
        run(args, WindowsRegistry(), root, report)
        return 0
    except RepairError as exc:
        report("未完成：" + str(exc))
        return 1
    except KeyboardInterrupt:
        report("已取消。如正在写入，请保留备份并检查当前配置。")
        return 130
    except Exception as exc:
        # Do not print raw third-party/configuration/OS exception messages.
        report(f"未完成：{type(exc).__name__}。请检查文件或注册表权限，保留备份；日志不包含配置原文。")
        return 1
    finally:
        report.save(root)


if __name__ == "__main__":
    raise SystemExit(main())
