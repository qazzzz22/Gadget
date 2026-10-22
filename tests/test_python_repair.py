"""Isolated regression tests; never write the real user's Environment key."""
from __future__ import annotations

import codecs
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import tomllib
import unittest
from unittest.mock import Mock, patch
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import codex_proxy_repair as app


class FakeRegistry:
    def __init__(self, home: Path):
        self.home = home
        self.values = {key: app.RegistryValue("http://127.0.0.1:7890") for key in app.KEYS[:3]}
        self.values["NO_PROXY"] = app.RegistryValue("*,.internal")
        self.writes = []
        self.fail_key = None

    def get(self, key):
        return self.values.get(key, app.RegistryValue())

    def set(self, key, value):
        if self.fail_key == key:
            self.fail_key = None
            raise PermissionError("injected registry failure")
        self.writes.append((key, value))
        self.values[key] = value

    def machine(self, key):
        return None

    def system_proxy(self):
        return None

    def codex_home(self):
        return self.home


class ProxyTests(unittest.TestCase):
    def test_normalizes_loopback_addresses(self):
        for source, expected in (("127.0.0.1:12345", "http://127.0.0.1:12345"),
                                 ("HTTP://LOCALHOST:7897/", "http://localhost:7897"),
                                 ("http://[::1]:7897", "http://[::1]:7897")):
            with self.subTest(source=source):
                self.assertEqual(app.normalize_proxy(source), expected)

    def test_rejects_remote_credentials_paths_and_injection(self):
        for source in ("http://example.com:80", "http://user:secret@127.0.0.1:7897",
                       "http://127.0.0.1:7897/path", "http://127.0.0.1:7897?",
                       "http://127.0.0.1:7897#", "http://127.0.0.1:70000",
                       "http://127.0.0.1:0", "http://127.0.0.1:7897 & calc",
                       "http://127.0.0.1\\:7897", "https://127.0.0.1:7897"):
            with self.subTest(source=source):
                self.assertIsNone(app.normalize_proxy(source))

    def test_socks_is_only_a_candidate_for_actual_http_validation(self):
        self.assertIsNone(app.normalize_proxy("socks5://127.0.0.1:12345"))
        self.assertEqual(app.normalize_proxy("socks5://127.0.0.1:12345", mixed_candidate=True), "http://127.0.0.1:12345")

    def test_redacts_remote_and_authenticated_values(self):
        for value in ("http://user:secret@127.0.0.1:7897", "http://company.example:3128"):
            self.assertNotIn("secret", app.safe_label(value))
            self.assertNotIn("company", app.safe_label(value))

    def test_no_proxy_removes_service_bypasses_and_preserves_others(self):
        value = "*,.openai.com,chatgpt.com,*.chatgpt.com,.internal,10.0.0.0/8,localhost"
        self.assertEqual(app.repair_no_proxy(value), ".internal,10.0.0.0/8,localhost,127.0.0.1,::1")

    def test_no_proxy_handles_ports_wildcards_and_ipv6(self):
        value = "CHATGPT.COM:443,*.com,[::1],::1,LOCALHOST"
        self.assertEqual(app.repair_no_proxy(value), "[::1],::1,LOCALHOST,127.0.0.1")

    def test_no_proxy_is_idempotent(self):
        value = app.repair_no_proxy(".internal")
        self.assertEqual(app.repair_no_proxy(value), value)


class DocumentTests(unittest.TestCase):
    def test_preserves_supported_encodings_and_boms(self):
        for bom, encoding in ((b"", "utf-8"), (codecs.BOM_UTF8, "utf-8"),
                              (codecs.BOM_UTF16_LE, "utf-16-le"), (codecs.BOM_UTF16_BE, "utf-16-be")):
            with self.subTest(encoding=encoding, bom=bom):
                text = "# 中文配置\r\nVALUE=unchanged\r\n"
                data = bom + text.encode(encoding)
                doc = app.Document.decode(data)
                self.assertEqual(doc.encode(doc.text), data)
                self.assertEqual(doc.encode(text + "# 新行"), bom + (text + "# 新行").encode(encoding))

    def test_rejects_invalid_utf8(self):
        with self.assertRaises(UnicodeError):
            app.Document.decode(b"\xffbad")

    def test_rejects_utf32_without_reinterpreting_it(self):
        with self.assertRaises(app.RepairError):
            app.Document.decode(codecs.BOM_UTF32_LE + "abc".encode("utf-32-le"))


class TomlTests(unittest.TestCase):
    def test_no_policy_does_not_create_one(self):
        text = "model='unchanged'\n"
        self.assertEqual(app.update_allowlist(text), text)

    def test_policy_without_allowlist_does_not_create_one(self):
        text = "[shell_environment_policy]\ninherit='all'\n"
        self.assertEqual(app.update_allowlist(text), text)

    def test_valid_arrays_comments_and_line_endings(self):
        for items in ('["PATH"]', '["PATH", # keep this comment\n]',
                      '["PATH" # no trailing comma\n]', '[]', '[# empty list\n]',
                      '["unusual]#name", "PATH"]', '["""PATH"""]'):
            for newline in ("\n", "\r\n"):
                with self.subTest(items=items, newline=repr(newline)):
                    text = ("model='unchanged'\n[shell_environment_policy]\ninclude_only=" + items +
                            "\n[desktop]\nlocale='zh-CN'\n").replace("\n", newline)
                    result = app.update_allowlist(text)
                    data = tomllib.loads(result)
                    self.assertEqual(data["model"], "unchanged")
                    self.assertEqual(data["desktop"]["locale"], "zh-CN")
                    self.assertIn("SystemRoot", data["shell_environment_policy"]["include_only"])
                    self.assertIn("NO_PROXY", data["shell_environment_policy"]["include_only"])
                    if "keep this comment" in text:
                        self.assertIn("keep this comment", result)
                    self.assertEqual(app.update_allowlist(result), result)

    def test_supports_quoted_table_and_key(self):
        result = app.update_allowlist('["shell_environment_policy"]\r\n"include_only"=["PATH"]\r\n')
        self.assertIn("SystemRoot", tomllib.loads(result)["shell_environment_policy"]["include_only"])

    def test_respects_case_insensitive_wildcard(self):
        text = "[shell_environment_policy]\ninclude_only=['*']\n"
        self.assertEqual(app.update_allowlist(text), text)

    def test_rejects_invalid_toml(self):
        with self.assertRaises(app.RepairError):
            app.update_allowlist("[shell_environment_policy]\ninclude_only=[")

    def test_preserves_restrictive_policy(self):
        for text in ("[shell_environment_policy]\ninherit='none'\ninclude_only=[]\n",
                     "[shell_environment_policy]\ninclude_only=[]\nexclude=['http*']\n",
                     "[shell_environment_policy]\ninclude_only=[1]\n"):
            with self.subTest(text=text), self.assertRaises(app.RepairError):
                app.update_allowlist(text)

    def test_declines_inline_policy_without_rewriting_document(self):
        with self.assertRaises(app.RepairError):
            app.update_allowlist("shell_environment_policy={include_only=['PATH']}\n")


class DotenvTests(unittest.TestCase):
    def test_updates_duplicates_case_quotes_comments_and_blank_lines(self):
        text = ("# heading\r\n\r\nexport http_proxy = 'http://127.0.0.1:7890' # old\r\n"
                "HTTP_PROXY=http://127.0.0.1:7890\r\nTOKEN=fake-test-only\r\nNO_PROXY=*,.internal\r\n")
        updated = app.update_dotenv(text, "http://127.0.0.1:12345", False)
        self.assertIn("# heading\r\n\r\n", updated)
        self.assertIn("export http_proxy = 'http://127.0.0.1:12345' # old", updated)
        self.assertIn("TOKEN=fake-test-only", updated)
        self.assertIn("NO_PROXY=.internal,localhost,127.0.0.1,::1", updated)
        self.assertEqual(app.update_dotenv(updated, "http://127.0.0.1:12345", False), updated)

    def test_does_not_treat_multiline_nonproxy_contents_as_assignments(self):
        text = 'TOKEN="first\nHTTP_PROXY=http://private.example:8080\nlast"\nHTTP_PROXY=http://127.0.0.1:7890\n'
        updated = app.update_dotenv(text, "http://127.0.0.1:12345", False)
        self.assertIn("HTTP_PROXY=http://private.example:8080", updated)
        self.assertEqual(updated.count("http://127.0.0.1:12345"), 1)

    def test_refuses_multiline_or_malformed_proxy_assignments(self):
        for text in ('HTTP_PROXY="unclosed\n', 'HTTP_PROXY="http://127.0.0.1:80" unexpected\n'):
            with self.subTest(text=text), self.assertRaises(app.RepairError):
                app.update_dotenv(text, "http://127.0.0.1:12345", False)

    def test_protects_remote_proxy_unless_explicitly_requested(self):
        text = "HTTP_PROXY=http://user:fake-password@company.example:3128\n"
        with self.assertRaises(app.RepairError):
            app.update_dotenv(text, "http://127.0.0.1:12345", False)
        self.assertEqual(app.update_dotenv(text, "http://127.0.0.1:12345", True), "HTTP_PROXY=http://127.0.0.1:12345\n")


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="codex-python-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "中文 path with spaces"
        self.root.mkdir()
        self.home = self.root / "codex-home"
        self.home.mkdir()
        self.tool = self.root / "tool"
        self.tool.mkdir()
        self.config = self.home / "config.toml"
        self.env = self.home / ".env"
        self.config.write_bytes(codecs.BOM_UTF8 + b"model='unchanged'\r\n[shell_environment_policy]\r\ninclude_only=['PATH']\r\n")
        self.env.write_bytes(codecs.BOM_UTF16_LE + "HTTP_PROXY=http://127.0.0.1:7890\r\nTOKEN=fake-only\r\n".encode("utf-16-le"))
        self.registry = FakeRegistry(self.home)
        self.original_values = copy.deepcopy(self.registry.values)
        self.original_files = (self.config.read_bytes(), self.env.read_bytes())

    def plan(self):
        return app.make_plan(self.registry, self.home, "http://127.0.0.1:12345")

    def apply(self):
        return app.apply_plan(self.plan(), self.registry, self.tool, self.home)

    def assert_original(self):
        self.assertEqual(self.registry.values, self.original_values)
        self.assertEqual((self.config.read_bytes(), self.env.read_bytes()), self.original_files)

    def test_apply_restore_and_exact_encoding_roundtrip(self):
        backup = self.apply()
        self.assertTrue(self.config.read_bytes().startswith(codecs.BOM_UTF8))
        self.assertTrue(self.env.read_bytes().startswith(codecs.BOM_UTF16_LE))
        self.assertEqual(app.latest_backup(self.tool), backup)
        app.restore_backup(backup, self.registry, self.home)
        self.assert_original()
        with self.assertRaises(app.RepairError):
            app.restore_backup(backup, self.registry, self.home)

    def test_repeated_repair_creates_no_extra_backup(self):
        self.apply()
        self.assertTrue(self.plan().empty)
        self.assertIsNone(app.apply_plan(self.plan(), self.registry, self.tool, self.home))

    def test_preserves_registry_type_and_absent_values(self):
        self.registry.values["HTTP_PROXY"] = app.RegistryValue("http://127.0.0.1:7890", 2)
        self.registry.values["ALL_PROXY"] = app.RegistryValue()
        before = copy.deepcopy(self.registry.values)
        backup = self.apply()
        self.assertEqual(self.registry.get("HTTP_PROXY").kind, 2)
        app.restore_backup(backup, self.registry, self.home)
        self.assertEqual(self.registry.values, before)

    def test_remote_user_proxy_is_protected(self):
        self.registry.values["HTTP_PROXY"] = app.RegistryValue("http://company.example:3128")
        with self.assertRaises(app.RepairError):
            self.plan()
        self.assertEqual(self.registry.writes, [])
        plan = app.make_plan(self.registry, self.home, "http://127.0.0.1:12345", True)
        self.assertTrue(plan.variables)

    def test_invalid_config_prevents_any_registry_write(self):
        self.config.write_text("[invalid TOML", encoding="utf-8")
        with self.assertRaises(app.RepairError):
            self.plan()
        self.assertEqual(self.registry.writes, [])

    def test_registry_failure_rolls_back_previous_variables(self):
        self.registry.fail_key = "HTTPS_PROXY"
        with self.assertRaisesRegex(app.RepairError, "已回滚"):
            self.apply()
        self.assert_original()

    def test_file_failure_rolls_back_written_files_and_registry(self):
        plan = self.plan()
        original_write = app.atomic_write
        failed = False
        def injected(path, data):
            nonlocal failed
            if path == self.env and not failed:
                failed = True
                raise PermissionError("injected file failure")
            return original_write(path, data)
        with patch.object(app, "atomic_write", side_effect=injected):
            with self.assertRaisesRegex(app.RepairError, "已回滚"):
                app.execute_changes(plan, self.registry)
        self.assert_original()

    def test_keyboard_interrupt_rolls_back_before_propagating(self):
        plan = self.plan()
        with patch.object(app, "atomic_write", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                app.execute_changes(plan, self.registry)
        self.assert_original()

    def test_preflight_rejects_file_race_before_any_registry_write(self):
        plan = self.plan()
        self.config.write_bytes(self.config.read_bytes() + b"# concurrent\n")
        with self.assertRaises(app.RepairError):
            app.apply_plan(plan, self.registry, self.tool, self.home)
        self.assertEqual(self.registry.writes, [])
        self.assertIn(b"# concurrent", self.config.read_bytes())

    def test_preflight_rejects_registry_race(self):
        plan = self.plan()
        self.registry.values["HTTP_PROXY"] = app.RegistryValue("http://127.0.0.1:6789")
        with self.assertRaises(app.RepairError):
            app.execute_changes(plan, self.registry)
        self.assertEqual(self.registry.writes, [])

    def test_failed_rollback_preserves_concurrent_registry_change(self):
        plan = self.plan()
        def fail_after_external_change(path, data):
            self.registry.values["HTTP_PROXY"] = app.RegistryValue("http://127.0.0.1:6789")
            raise PermissionError("injected")
        with patch.object(app, "atomic_write", side_effect=fail_after_external_change):
            with self.assertRaisesRegex(app.RepairError, "部分项目"):
                app.execute_changes(plan, self.registry)
        self.assertEqual(self.registry.get("HTTP_PROXY").value, "http://127.0.0.1:6789")

    def test_restore_refuses_later_file_changes_without_partial_env_writes(self):
        backup = self.apply()
        after = copy.deepcopy(self.registry.values)
        self.config.write_bytes(self.config.read_bytes() + b"# later\n")
        with self.assertRaises(app.RepairError):
            app.restore_backup(backup, self.registry, self.home)
        self.assertEqual(self.registry.values, after)

    def test_restore_refuses_later_registry_changes(self):
        backup = self.apply()
        self.registry.values["HTTP_PROXY"] = app.RegistryValue("http://127.0.0.1:6789")
        count = len(self.registry.writes)
        with self.assertRaises(app.RepairError):
            app.restore_backup(backup, self.registry, self.home)
        self.assertEqual(len(self.registry.writes), count)

    def test_restore_failure_rolls_back_to_repaired_state(self):
        backup = self.apply()
        values = copy.deepcopy(self.registry.values)
        files = (self.config.read_bytes(), self.env.read_bytes())
        self.registry.fail_key = "HTTPS_PROXY"
        with self.assertRaises(app.RepairError):
            app.restore_backup(backup, self.registry, self.home)
        self.assertEqual(self.registry.values, values)
        self.assertEqual((self.config.read_bytes(), self.env.read_bytes()), files)

    def test_restore_detects_modified_backup(self):
        backup = self.apply()
        (backup / "file-0.before").write_bytes(b"changed backup")
        with self.assertRaises(app.RepairError):
            app.restore_backup(backup, self.registry, self.home)

    def test_restore_rejects_other_owner_home_and_path_traversal(self):
        backup = self.apply()
        path = backup / "manifest.json"
        original = json.loads(path.read_text(encoding="utf-8"))
        for transform in (lambda m: m.update(owner="another-user"),
                          lambda m: m.update(home=str(self.tool)),
                          lambda m: m["files"][0].update(backup="../elsewhere"),
                          lambda m: m["files"][0].update(path=str(self.tool / "unrelated"))):
            manifest = copy.deepcopy(original)
            transform(manifest)
            path.write_text(json.dumps(manifest), encoding="utf-8")
            with self.assertRaises(app.RepairError):
                app.restore_backup(backup, self.registry, self.home)

    def test_hardlinked_configuration_is_not_modified(self):
        linked = self.home / "linked"
        try:
            os.link(self.config, linked)
        except OSError:
            self.skipTest("hard links are unavailable")
        with self.assertRaises(app.RepairError):
            self.plan()

    def test_diagnose_only_shows_plan(self):
        args = Mock(mode="diagnose", proxy_url=None, timeout=3)
        report = app.Reporter()
        with patch.object(app, "candidates", return_value=["http://127.0.0.1:12345"]), \
             patch.object(app, "port_open", return_value=True), \
             patch.object(app, "probe_proxy", return_value=app.Probe(405)), \
             patch("sys.stdout", io.StringIO()):
            app.run(args, self.registry, self.tool, report)
        self.assert_original()
        self.assertEqual(self.registry.writes, [])
        self.assertFalse((self.tool / "python-backups").exists())

    def test_no_valid_route_makes_no_changes(self):
        args = Mock(mode="repair", proxy_url=None, timeout=3)
        with patch.object(app, "candidates", return_value=["http://127.0.0.1:12345"]), \
             patch.object(app, "port_open", return_value=False), patch("sys.stdout", io.StringIO()):
            with self.assertRaises(app.RepairError):
                app.run(args, self.registry, self.tool, app.Reporter())
        self.assert_original()
        self.assertEqual(self.registry.writes, [])

    def test_candidate_sources_arbitrary_port_and_deduplication(self):
        folder = self.root / "roaming" / "io.github.clash-verge-rev.clash-verge-rev"
        folder.mkdir(parents=True)
        (folder / "clash-verge.yaml").write_bytes(b"mixed-port: 23456\r\n")
        self.registry.values["HTTP_PROXY"] = app.RegistryValue("socks5://127.0.0.1:23456")
        with patch.object(app, "process_ports", return_value=[]), patch.dict(os.environ, {}, clear=True):
            found = app.candidates(self.registry, self.home, roaming=folder.parent)
        self.assertEqual(found.count("http://127.0.0.1:23456"), 1)
        self.assertNotIn("company.example", str(found))


class NetworkTests(unittest.TestCase):
    def test_https_probe_uses_explicit_tunnel_and_verifies_certificates(self):
        connection = Mock()
        connection.getresponse.return_value.status = 405
        with patch.object(app.http.client, "HTTPSConnection", return_value=connection) as constructor:
            result = app.probe_proxy("http://127.0.0.1:12345")
        self.assertTrue(result.usable)
        connection.set_tunnel.assert_called_once_with("chatgpt.com", 443)
        context = constructor.call_args.kwargs["context"]
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        connection.close.assert_called_once()

    def test_error_statuses_do_not_pass(self):
        for code in (403, 407, 429, 500):
            with self.subTest(code=code):
                self.assertFalse(app.Probe(code).usable)
        for code in (200, 302, 401, 405):
            with self.subTest(code=code):
                self.assertTrue(app.Probe(code).usable)

    def test_network_exceptions_are_redacted_and_classified(self):
        for error, expected in ((ssl.SSLCertVerificationError("secret"), "certificate"),
                                (ssl.SSLError("secret"), "tls"), (TimeoutError("secret"), "timeout"),
                                (OSError("407 fake-secret"), "proxy_auth"), (ConnectionRefusedError("secret"), "connection")):
            connection = Mock()
            connection.request.side_effect = error
            with self.subTest(expected=expected), patch.object(app.http.client, "HTTPSConnection", return_value=connection):
                result = app.probe_proxy("http://127.0.0.1:12345")
                self.assertEqual(result.error, expected)
                self.assertNotIn("secret", repr(result))
                self.assertFalse(result.usable)

    def local_proxy(self, response):
        observed = []
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                request = b""
                while b"\r\n\r\n" not in request and len(request) < 8192:
                    part = self.request.recv(1024)
                    if not part:
                        return
                    request += part
                observed.append(request)
                self.request.sendall(response)
        server = socketserver.TCPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_address[1]}", observed

    def test_real_local_connect_407_ignores_stale_env_and_no_proxy(self):
        address, observed = self.local_proxy(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1", "NO_PROXY": "*"}):
            result = app.probe_proxy(address, timeout=3)
        self.assertEqual(result.error, "proxy_auth")
        self.assertIn(b"CONNECT chatgpt.com:443", observed[0])
        self.assertNotIn(b"Authorization:", observed[0])

    def test_real_local_connect_cannot_fake_tls_success(self):
        address, observed = self.local_proxy(b"HTTP/1.1 200 Connection established\r\n\r\n")
        result = app.probe_proxy(address, timeout=3)
        self.assertFalse(result.usable)
        self.assertTrue(observed)

    def test_tcp_port_discovery_detects_listener(self):
        address, _ = self.local_proxy(b"")
        self.assertTrue(app.port_open(address))


@unittest.skipUnless(os.name == "nt", "Windows integration")
class WindowsTests(unittest.TestCase):
    def test_registry_roundtrip_uses_an_isolated_non_environment_key(self):
        import winreg
        key = "Software\\CodexProxyRepairTests-" + uuid.uuid4().hex
        registry = app.WindowsRegistry(user_key=key)
        self.addCleanup(lambda: winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key))
        self.assertIsNone(registry.get("HTTP_PROXY").value)
        registry.set("HTTP_PROXY", app.RegistryValue("%TEMP%/fake-proxy", winreg.REG_EXPAND_SZ))
        self.assertEqual(registry.get("HTTP_PROXY"), app.RegistryValue("%TEMP%/fake-proxy", winreg.REG_EXPAND_SZ))
        registry.set("HTTP_PROXY", app.RegistryValue())
        self.assertIsNone(registry.get("HTTP_PROXY").value)
        with self.assertRaises(app.RepairError):
            registry.set("UNRELATED", app.RegistryValue("no"))

    def test_python_launcher_finds_existing_runtime_without_powershell(self):
        environment = dict(os.environ, CODEX_PROXY_REPAIR_NOPAUSE="1", CODEX_PRIMARY_RUNTIME_PYTHON=sys.executable)
        result = subprocess.run([str(app.windows_binary("cmd.exe")), "/d", "/c", str(ROOT / "Python-仅诊断.cmd"), "--help"],
                                capture_output=True, timeout=20, env=environment)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace") + result.stdout.decode(errors="replace"))
        self.assertIn(b"--mode", result.stdout)

    def test_missing_python_exits_without_opening_windows_store(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ, CODEX_PROXY_REPAIR_NOPAUSE="1", USERPROFILE=directory,
                               LOCALAPPDATA=directory, CODEX_PRIMARY_RUNTIME_PYTHON="", PATH=str(app.windows_binary("cmd.exe").parent))
            result = subprocess.run([str(app.windows_binary("cmd.exe")), "/d", "/c", str(ROOT / "Python-仅诊断.cmd")],
                                    capture_output=True, timeout=20, env=environment)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"not found", result.stdout)

    def test_atomic_replace_preserves_private_existing_acl(self):
        import ctypes
        from ctypes import wintypes
        security = ctypes.WinDLL("advapi32", use_last_error=True).GetFileSecurityW
        security.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        security.restype = wintypes.BOOL
        def acl(path):
            length = wintypes.DWORD()
            security(str(path), 4, None, 0, ctypes.byref(length))
            buffer = ctypes.create_string_buffer(length.value)
            if not security(str(path), 4, buffer, length.value, ctypes.byref(length)):
                raise ctypes.WinError(ctypes.get_last_error())
            return buffer.raw
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = root / "private"
            app.private_directory(secret)
            source = secret / "original"
            source.write_bytes(b"before")
            target = root / "config.toml"
            source.replace(target)
            original = acl(target)
            app.atomic_write(target, b"after")
            replaced = acl(target)
            def dacl(descriptor):
                offset = int.from_bytes(descriptor[16:20], "little")
                length = int.from_bytes(descriptor[offset + 2:offset + 4], "little")
                return descriptor[offset:offset + length]
            # ReplaceFile may change auto-inheritance/protection control bits.
            # Compare the actual access-control entries, not those bookkeeping bits.
            self.assertEqual(dacl(replaced), dacl(original))
            if int.from_bytes(original[2:4], "little") & 0x1000:
                self.assertTrue(int.from_bytes(replaced[2:4], "little") & 0x1000)
            self.assertEqual(target.read_bytes(), b"after")

    def test_staging_file_is_restricted_while_still_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.toml"
            path.write_bytes(b"before")
            protect = app.private_file
            observed = []
            def restricted_while_empty(staging):
                observed.append(staging.read_bytes())
                return protect(staging)
            with patch.object(app, "private_file", side_effect=restricted_while_empty):
                app.atomic_write(path, b"fake-private-configuration")
            self.assertEqual(observed, [b""])
            self.assertEqual(path.read_bytes(), b"fake-private-configuration")


class PackageTests(unittest.TestCase):
    def test_release_contains_only_allowlisted_python_files_and_is_reproducible(self):
        spec = importlib.util.spec_from_file_location("release_builder", ROOT / "tools" / "build_python_release.py")
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = builder.build(root / "one")
            second = builder.build(root / "two")
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                names = archive.namelist()
                self.assertEqual(len(names), 7)
                self.assertFalse(any(name.endswith(".ps1") or "backups" in name or "logs" in name for name in names))
                command = archive.read(next(name for name in names if name.endswith("run-python.cmd")))
                self.assertNotIn(b"powershell", command.lower())
                self.assertIn(b"\r\n", command)
                self.assertNotIn(b"\n", command.replace(b"\r\n", b""))
            self.assertIn(app.digest(first.read_bytes()), first.with_suffix(".zip.sha256").read_text(encoding="ascii"))
            with self.assertRaises(FileExistsError):
                builder.build(root / "one")


if __name__ == "__main__":
    unittest.main()
