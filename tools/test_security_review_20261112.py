"""Bounded, synthetic security review. Run with python -B tools/test_security_review_20261112.py.

Only the two reviewed sources and this test file are read. Source definitions are
loaded through AST, without executing module initialization or reading the real
environment. HTTP, paths, commands, and archives stay in memory. The audit hook
rejects real writes, subprocesses, and network operations. Every security
invariant is an ordinary regression: an unfixed scenario fails the test run.
"""

import ast
import base64
import hashlib
import html
import http.cookies
import http.server
import io
import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
import tomllib
import unittest
import urllib.parse
from contextlib import nullcontext
from email.parser import Parser
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
PANEL_PATH = ROOT / "trusttunnel-panel.py"
INSTALLER_PATH = ROOT / "install-trusttunnel-warp.sh"
PANEL_BYTES = PANEL_PATH.read_bytes()
INSTALLER_BYTES = INSTALLER_PATH.read_bytes()
PANEL_SOURCE = PANEL_BYTES.decode("utf-8-sig").replace("\r\n", "\n")
INSTALLER_SOURCE = INSTALLER_BYTES.decode("utf-8-sig").replace("\r\n", "\n")
PANEL_TREE = ast.parse(PANEL_SOURCE, filename=str(PANEL_PATH))
DEFINITIONS = {
    "Handler", "PanelServer", "DeadlineReader", "login_delay", "panel_auth_failure", "client_name_valid", "validate_port",
    "normalized_ip", "admin_peer", "firewall_rule", "jail_name", "confirmed",
    "fail2ban_operation", "installer_operation", "interface_operation",
    "backup_archive", "recent_logs", "diagnostic_report", "power_operation",
    "redeem_enrollment", "protection_operation", "tls_auth_operation", "panel_event", "main",
}
REVIEW_TREE = ast.Module(
    body=[node for node in PANEL_TREE.body
          if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in DEFINITIONS],
    type_ignores=[],
)
REVIEW_CODE = compile(REVIEW_TREE, str(PANEL_PATH), "exec")
TOTAL_READ_SECONDS = 20
PER_PEER_CONNECTIONS = 4


class MemoryPath:
    def __init__(self, files, value):
        self.files = files
        self.value = str(value)

    def __str__(self):
        return self.value

    def __truediv__(self, other):
        return MemoryPath(self.files, str(PurePosixPath(self.value) / str(other)))

    @property
    def name(self):
        return PurePosixPath(self.value).name

    @property
    def parent(self):
        return MemoryPath(self.files, PurePosixPath(self.value).parent)

    def exists(self):
        return self.value in self.files

    def is_file(self):
        return self.exists()

    def is_symlink(self):
        return self.value.endswith(".symlink")

    def read_bytes(self):
        return self.files[self.value]

    def read_text(self, encoding="utf-8"):
        return self.read_bytes().decode(encoding)

    def relative_to(self, other):
        return PurePosixPath(self.value).relative_to(str(other))

    def rglob(self, pattern):
        if pattern != "*":
            raise AssertionError("Unexpected virtual glob")
        return [MemoryPath(self.files, value) for value in self.files
                if value.startswith(self.value.rstrip("/") + "/")]


class MemoryConnection:
    def __init__(self, request):
        self.request = io.BytesIO(request)
        self.response = bytearray()
        self.timeout = None

    def makefile(self, mode, *args):
        if mode != "rb":
            raise AssertionError("Unexpected socket stream")
        return io.BytesIO(self.request.getvalue())

    def sendall(self, data):
        self.response.extend(data)

    def settimeout(self, value):
        self.timeout = value

    def gettimeout(self):
        return self.timeout

    def getsockname(self):
        return ("127.0.0.1", 8088)

    def recv(self, size, flags=0):
        return self.request.read(size)

    def recv_into(self, buffer, size=0, flags=0):
        data = self.recv(size or len(buffer), flags)
        buffer[:len(data)] = data
        return len(data)

    def close(self):
        pass


class MemoryTLSConnection(MemoryConnection):
    pass


class DelayedRaw(io.RawIOBase):
    def __init__(self, connection):
        self.connection = connection

    def readable(self):
        return True

    def readinto(self, buffer):
        return self.connection.recv_into(buffer, min(1, len(buffer)))


class SlowMemoryConnection(MemoryConnection):
    def __init__(self, request):
        super().__init__(request)
        self.elapsed = 0
        self.header_end = request.index(b"\r\n\r\n") + 4
        self.request_line_end = request.index(b"\r\n") + 2

    def read_delay(self, position):
        return 19

    def recv(self, size, flags=0):
        if not size or self.request.tell() == len(self.request.getvalue()):
            return b""
        delay = self.read_delay(self.request.tell())
        if self.timeout is not None and delay > self.timeout:
            self.elapsed += max(0, self.timeout)
            raise TimeoutError("Synthetic socket read timeout")
        self.elapsed += delay
        return self.request.read(1)

    def makefile(self, mode, *args):
        if mode != "rb":
            raise AssertionError("Unexpected socket stream")
        return io.BufferedReader(DelayedRaw(self))


class SlowHeaderConnection(SlowMemoryConnection):
    def read_delay(self, position):
        return 1 if position >= self.request_line_end else 0


class SlowBodyConnection(SlowMemoryConnection):
    def read_delay(self, position):
        return 1 if position >= self.header_end else 0


class SharedReadBudgetConnection(SlowBodyConnection):
    def read_delay(self, position):
        return 12 if position == self.header_end - 1 else super().read_delay(position)


def shell_function(name):
    match = re.search(r"(?ms)^" + re.escape(name) + r"\(\) \{\n(.*?)^\}", INSTALLER_SOURCE)
    if not match:
        raise AssertionError("Reviewed shell function not found: " + name)
    return match.group(1)


def fresh_namespace():
    files = {}
    path = lambda value: MemoryPath(files, value)
    os_stub = SimpleNamespace(
        environ={}, close=Mock(), chmod=Mock(), replace=Mock(),
        path=SimpleNamespace(exists=Mock(return_value=False)),
    )
    namespace = dict(
        __name__="synthetic_security_review", __file__=str(PANEL_PATH),
        base64=base64, hashlib=hashlib, html=html, http=http, io=io,
        ipaddress=ipaddress, json=json, re=re, secrets=secrets, socket=socket, sqlite3=sqlite3,
        ssl=SimpleNamespace(SSLSocket=MemoryTLSConnection), sys=sys,
        threading=threading, time=time, tomllib=tomllib, urllib=urllib, os=os_stub, Path=path,
        PANEL_USER="synthetic-admin", PANEL_PASSWORD="synthetic-password-only",
        PANEL_BIND="127.0.0.1", PANEL_PORT=8088,
        PANEL_TLS=False, PANEL_CERT="synthetic-cert", PANEL_KEY="synthetic-key",
        CSRF_TOKEN="synthetic-csrf-not-a-real-secret", SESSION_IDLE_SECONDS=1800,
        SESSION_MAX_SECONDS=43200, SESSIONS={}, SESSION_LOCK=threading.Lock(),
        LOGIN_FAILURES={}, LOGIN_LOCK=threading.Lock(), CACHE_LOCK=threading.Lock(),
        PANEL_EVENTS={}, PANEL_EVENTS_LOCK=threading.Lock(),
        SNAPSHOT_CACHE={}, CACHE_COMPUTE_LOCKS={}, DEEPLINK_CACHE={}, NAV_ITEMS=[("dashboard", "Dashboard")],
        ASSET_VERSION="synthetic", PANEL_STYLE="synthetic-css",
        CONSOLE_SCRIPT="synthetic-js", LOGIN_STYLE="synthetic-login-css",
        TT_DIR=path("/opt/trusttunnel"), CLIENT_DIR=path("/root/trusttunnel-clients"),
        INTERFACE_DIR=path("/opt/warp-interface"),
        INTERFACE_DROPIN=path("/etc/systemd/system/trusttunnel.service.d/40-warp-interface.conf"),
        MASQUE_DIR=path("/opt/warp-masque"), SOCKS_ADDR="127.0.0.1:40000",
        MASQUE_ADDR="127.0.0.1:40002", admin_lock=nullcontext,
        run=Mock(return_value=(0, "synthetic-command-output")),
        checked_run=Mock(return_value="synthetic-command-output"),
        atomic_write=Mock(), audit_log=Mock(), subprocess=SimpleNamespace(Popen=Mock()),
        require_no_firewall_pending=Mock(), strict_protection_locked=Mock(return_value=False),
        interface_enabled=Mock(return_value=False),
        domain=Mock(return_value="panel.example"),
        current_panel_env=Mock(return_value={"PANEL_BIND": "127.0.0.1", "PANEL_PORT": "8088", "PANEL_TLS": "0"}),
        protection_state=Mock(return_value={}),
        endpoint_capabilities=Mock(return_value={"prefix": True, "auth_key": False}),
        quic_enabled=Mock(return_value=False),
        commit_protection_rules=Mock(), apply_endpoint_file=Mock(),
        load_clients=Mock(return_value=[{"username": "alice", "password": "synthetic-client-only"}]),
        admin_operation=Mock(return_value="synthetic-result"),
        monitor_snapshot=Mock(return_value={}), release_snapshot=Mock(return_value={}),
        client_metrics=Mock(return_value={"clients": []}),
        health_snapshot=Mock(return_value={"state": "unknown"}),
        scanner_snapshot=Mock(return_value={"counts": {}}),
        fail2ban_snapshot=Mock(return_value={"configured": ["sshd"], "active": ["sshd"]}),
        PANEL_LOGIN_JAIL="trusttunnel-panel-login",
        panel_login_protection_status=Mock(return_value={"enabled": False}),
        protected_ports=Mock(return_value=[(22, "tcp"), (443, "tcp"), (8088, "tcp")]),
        html_page=Mock(return_value="<main>synthetic-private-dashboard</main>"),
        login_page=lambda token, nonce, error: '<input name="_login_token" value="' + token + '">',
        activation_page=lambda token, nonce: '<input name="_csrf" value="' + token + '">',
        deeplink=Mock(return_value="tt://?synthetic"), qr_image=Mock(return_value=b"synthetic-png"),
        enrollment_identity=Mock(return_value="synthetic-identity"),
        tempfile=SimpleNamespace(mkstemp=Mock(return_value=(123456, "/root/.synthetic-archive"))),
        zipfile=SimpleNamespace(ZIP_DEFLATED=8, ZipFile=Mock()),
        read_text=lambda value: files.get(str(value), b"").decode("utf-8"),
    )
    exec(REVIEW_CODE, namespace)
    return namespace, files


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.p, self.files = fresh_namespace()
        parent = self.p["Handler"]

        class QuietHandler(parent):
            def log_message(self, *args):
                pass

        self.handler = QuietHandler
        self.auth = "Basic " + base64.b64encode(b"synthetic-admin:synthetic-password-only").decode()

    def request(self, path="/", method="GET", values=None, body=None, headers=(), auth=False,
                tls=False, peer="127.0.0.1", pipeline=b"", connection_type=None, auto_host=True):
        if values is not None:
            body = urllib.parse.urlencode(values).encode()
        if body is None:
            body = b""
        given = {key.lower() for key, value in headers}
        fields = []
        for key, value in (("Host", "panel.example:8088"), ("Accept", "application/json")):
            if key.lower() not in given and (key != "Host" or auto_host):
                fields.append((key, value))
        if auth:
            fields.append(("Authorization", self.auth))
        if method == "POST":
            if "content-type" not in given:
                fields.append(("Content-Type", "application/x-www-form-urlencoded"))
            if "content-length" not in given:
                fields.append(("Content-Length", str(len(body))))
        fields.extend(headers)
        wire = (method + " " + path + " HTTP/1.1\r\n" +
                "\r\n".join(key + ": " + value for key, value in fields) + "\r\n\r\n").encode("ascii")
        connection_type = connection_type or (MemoryTLSConnection if tls else MemoryConnection)
        connection = connection_type(wire + body + pipeline)
        self.last_connection = connection
        if isinstance(connection, SlowMemoryConnection):
            self.p["time"] = SimpleNamespace(monotonic=lambda: connection.elapsed, time=time.time)
        server_context = SimpleNamespace(server_address=("127.0.0.1", 8088), server_port=8088,
                                         server_name="panel.example")
        self.handler(connection, (peer, 12345), server_context)
        raw = bytes(connection.response)
        if not raw:
            return 0, Parser().parsestr(""), b""
        head, payload = raw.split(b"\r\n\r\n", 1)
        status = int(head.split(b" ", 2)[1])
        parsed = Parser().parsestr(head.split(b"\r\n", 1)[1].decode("iso-8859-1"))
        return status, parsed, payload

    def memory_server(self):
        with patch.object(http.server.ThreadingHTTPServer, "__init__", return_value=None):
            server = self.p["PanelServer"](("127.0.0.1", 8088), self.handler)
        server.shutdown_request = Mock()
        return server

    def assert_read_deadline(self, connection_type, path="/health", **kwargs):
        status, headers, body = self.request(path, connection_type=connection_type, **kwargs)
        self.assertLessEqual(self.last_connection.elapsed, TOTAL_READ_SECONDS,
                             "Request held a worker for simulated %ss (status %s)" %
                             (self.last_connection.elapsed, status))
        self.assertTrue(status == 0 or 400 <= status < 500,
                        "An incomplete over-budget request must close or receive a client error")
        self.p["admin_operation"].assert_not_called()
        self.p["html_page"].assert_not_called()
        self.assertFalse(self.p["SESSIONS"])

    def post(self, values, **kwargs):
        return self.request("/manage", method="POST", values=values, **kwargs)

    def csrf_values(self, **kwargs):
        return dict(action="monitor", _csrf=self.p["CSRF_TOKEN"], **kwargs)

    def seed_session(self, token="synthetic-session", age=0, idle=0):
        now = time.monotonic()
        self.p["SESSIONS"][hashlib.sha256(token.encode()).hexdigest()] = {
            "created": now - age, "seen": now - idle,
        }
        return "tt_session=" + token

    def test_public_routes_have_no_private_backend_calls(self):
        for path in ("/health", "/login", "/activate", "/public/login.css"):
            with self.subTest(path=path):
                status, headers, body = self.request(path)
                self.assertEqual(status, 200)
                self.assertNotIn(self.p["CSRF_TOKEN"].encode(), body)
                self.assertEqual(headers["Cache-Control"], "no-store")
        self.p["html_page"].assert_not_called()
        self.p["load_clients"].assert_not_called()
        self.p["admin_operation"].assert_not_called()

    def test_private_routes_and_public_route_variants_require_auth(self):
        for path in ("/", "/api/client-link?username=alice", "/api/clients-metrics",
                     "/api/monitor", "/api/releases", "/api/server-health", "/api/panel-protection", "/backup/latest.zip",
                     "/client/alice/http2.toml", "/qr-link/alice.png",
                     "/assets/synthetic.js", "/login?x=1", "/activate/", "/health?x=1"):
            with self.subTest(path=path):
                self.assertEqual(self.request(path)[0], 401)
        self.p["html_page"].assert_not_called()
        self.p["load_clients"].assert_not_called()
        self.p["health_snapshot"].assert_not_called()
        self.p["scanner_snapshot"].assert_not_called()

    def test_unauthenticated_post_cannot_render_dashboard_or_execute(self):
        for path in ("/manage", "/installer", "/panel/credentials", "/unrecognized"):
            status, headers, body = self.request(path, method="POST", body=b"x", headers=(("Content-Length", "bad"),))
            self.assertEqual(status, 401)
            self.assertNotIn(b"synthetic-private-dashboard", body)
        self.p["html_page"].assert_not_called()
        self.p["admin_operation"].assert_not_called()
        self.p["run"].assert_not_called()

    def test_missing_panel_password_fails_closed(self):
        self.p["PANEL_PASSWORD"] = ""
        self.assertEqual(self.request(auth=True)[0], 503)
        self.assertEqual(self.post(self.csrf_values(), auth=True)[0], 503)

    def test_html_request_does_not_accept_browser_cached_basic_auth(self):
        status, headers, body = self.request(auth=True, headers=(("Accept", "text/html"),))
        self.assertEqual(status, 303)
        self.assertEqual(headers["Location"], "/login")

    def test_basic_auth_and_cookie_auth_are_both_supported(self):
        self.assertEqual(self.request(auth=True)[0], 200)
        cookie = self.seed_session()
        self.assertEqual(self.request(headers=(("Cookie", cookie),))[0], 200)

    def test_stored_session_hash_is_not_a_bearer_token(self):
        self.seed_session()
        digest = next(iter(self.p["SESSIONS"]))
        self.assertEqual(self.request(headers=(("Cookie", "tt_session=" + digest),))[0], 401)

    def test_idle_and_absolute_expiration(self):
        for age, idle in ((0, 1801), (43201, 0)):
            self.p["SESSIONS"].clear()
            cookie = self.seed_session(age=age, idle=idle)
            self.assertEqual(self.request(headers=(("Cookie", cookie),))[0], 401)
            self.assertFalse(self.p["SESSIONS"])

    def test_basic_throttle_uses_socket_peer_not_forwarded_header(self):
        codes = []
        for index in range(6):
            codes.append(self.request(headers=(("Authorization", "Basic invalid"),
                                               ("X-Forwarded-For", "192.0.2." + str(index))))[0])
        self.assertEqual(codes, [401] * 5 + [429])

    def test_login_requires_matching_double_submit_token(self):
        values = {"username": "synthetic-admin", "password": "synthetic-password-only", "_login_token": "a"}
        self.assertEqual(self.request("/login", method="POST", values=values,
                                      headers=(("Cookie", "tt_login=b"),))[0], 403)
        self.assertFalse(self.p["SESSIONS"])

    def test_login_session_and_logout(self):
        status, headers, body = self.request("/login")
        token = re.search(rb'value="([^"]+)"', body)[1].decode()
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        status, headers, body = self.request("/login", method="POST", values={
            "username": "synthetic-admin", "password": "synthetic-password-only", "_login_token": token,
        }, headers=(("Cookie", cookie), ("Origin", "http://panel.example:8088")))
        self.assertEqual(status, 303)
        cookies = http.cookies.SimpleCookie()
        for value in headers.get_all("Set-Cookie", []):
            cookies.load(value)
        session = cookies["tt_session"]
        self.assertTrue(session["httponly"])
        self.assertEqual(session["samesite"], "Strict")
        self.assertEqual(session["path"], "/")
        self.assertIn(hashlib.sha256(session.value.encode()).hexdigest(), self.p["SESSIONS"])
        cookie = "tt_session=" + session.value
        self.assertEqual(self.request(headers=(("Cookie", cookie),))[0], 200)
        self.assertEqual(self.request("/logout", method="POST", values={"_csrf": self.p["CSRF_TOKEN"]},
                                      headers=(("Cookie", cookie),))[0], 303)
        self.assertFalse(self.p["SESSIONS"])
        self.assertEqual(self.request(headers=(("Cookie", cookie),))[0], 401)

    def test_tls_cookies_use_host_prefix_and_secure(self):
        status, headers, body = self.request("/login", tls=True)
        cookie = http.cookies.SimpleCookie(headers["Set-Cookie"])["__Host-tt_login"]
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"], "Strict")
        self.assertEqual(cookie["path"], "/")
        self.assertFalse(cookie["domain"])
        self.assertIsNotNone(headers["Strict-Transport-Security"])

    def test_missing_wrong_and_unicode_csrf_do_not_execute(self):
        for token in ("", "wrong", "\u043d\u0435\u0432\u0435\u0440\u043d\u043e"):
            self.assertEqual(self.post({"action": "monitor", "_csrf": token}, auth=True)[0], 403)
        self.p["admin_operation"].assert_not_called()

    def test_cross_origin_mutations_and_login_are_rejected(self):
        bad_origin = (("Origin", "https://attacker.invalid"),)
        self.assertEqual(self.post(self.csrf_values(), auth=True, headers=bad_origin)[0], 403)
        self.assertEqual(self.request("/login", method="POST", values={}, headers=bad_origin)[0], 403)
        self.p["admin_operation"].assert_not_called()

    def test_origin_omission_still_requires_valid_auth_and_csrf(self):
        self.assertEqual(self.post(self.csrf_values())[0], 401)
        self.assertEqual(self.post({"action": "monitor"}, auth=True)[0], 403)
        self.assertEqual(self.post(self.csrf_values(), auth=True)[0], 200)
        self.p["admin_operation"].assert_called_once()

    def test_forged_host_origin_alone_cannot_bypass_authentication(self):
        headers = (("Host", "attacker.invalid"), ("Origin", "http://attacker.invalid"))
        self.assertIn(self.post(self.csrf_values(), headers=headers)[0], (400, 403, 421))
        self.p["admin_operation"].assert_not_called()

    def test_arbitrary_host_and_matching_origin_are_rejected_even_with_valid_auth_csrf(self):
        headers = (("Host", "attacker.invalid"), ("Origin", "http://attacker.invalid"))
        self.assertIn(self.post(self.csrf_values(), auth=True, headers=headers)[0], (400, 403, 421))
        self.p["admin_operation"].assert_not_called()

    def test_canonical_hosts_remain_usable(self):
        for host in ("panel.example:8088", "PANEL.EXAMPLE:8088", "127.0.0.1:8088", "localhost:8088"):
            with self.subTest(host=host):
                self.assertEqual(self.request("/health", headers=(("Host", host),))[0], 200)

    def test_malformed_wrong_port_and_suffix_hosts_are_rejected(self):
        for host in ("", "panel.example.attacker.invalid:8088", "panel.example:8089",
                     "panel.example:8088@attacker.invalid", "panel.example:8088/path",
                     "panel.example:8088#fragment", "panel.example:8088,attacker.invalid"):
            with self.subTest(host=host):
                self.assertIn(self.request("/health", headers=(("Host", host),))[0], (400, 403, 421))

    def test_missing_and_duplicate_host_headers_are_rejected(self):
        variants = ((), (("Host", "panel.example:8088"), ("Host", "panel.example:8088")),
                    (("Host", "panel.example:8088"), ("Host", "attacker.invalid")),
                    (("Host", ""), ("Host", "panel.example:8088")))
        for headers in variants:
            with self.subTest(headers=headers):
                self.assertIn(self.request("/health", headers=headers, auto_host=False)[0], (400, 403, 421))

    def test_unknown_host_cannot_issue_public_login_or_activation_cookies(self):
        for path in ("/login", "/activate", "/public/login.css"):
            with self.subTest(path=path):
                status, headers, body = self.request(path, headers=(("Host", "attacker.invalid"),))
                self.assertIn(status, (400, 403, 421))
                self.assertFalse(headers.get_all("Set-Cookie", []))
        self.assertFalse(self.p["SESSIONS"])

    def test_forwarded_host_does_not_override_socket_host_validation(self):
        headers = (("Host", "attacker.invalid"), ("Origin", "http://attacker.invalid"),
                   ("X-Forwarded-Host", "panel.example:8088"), ("Forwarded", "host=panel.example:8088"))
        self.assertIn(self.post(self.csrf_values(), auth=True, headers=headers)[0], (400, 403, 421))
        self.p["admin_operation"].assert_not_called()

    def test_identity_aliases_are_canonicalized_before_dispatch(self):
        self.assertEqual(self.post(self.csrf_values(vpn_client_name="alice"), auth=True)[0], 200)
        values = self.p["admin_operation"].call_args.args[1]
        self.assertEqual(values["username"], "alice")
        self.assertNotIn("vpn_client_name", values)
        self.assertEqual(self.post(self.csrf_values(panel_login="synthetic-admin", panel_password="synthetic-password"), auth=True)[0], 200)
        values = self.p["admin_operation"].call_args.args[1]
        self.assertEqual(values["username"], "synthetic-admin")
        self.assertEqual(values["password"], "synthetic-password")
        self.assertNotIn("panel_login", values)
        self.assertNotIn("panel_password", values)

    def test_identity_alias_collisions_are_rejected(self):
        for identity in ({"vpn_client_name": "alice", "username": "alice"},
                         {"panel_login": "admin", "username": "admin"},
                         {"panel_password": "x", "password": "x"},
                         {"vpn_client_name": "alice", "panel_login": "alice"}):
            with self.subTest(identity=identity):
                self.assertEqual(self.post(self.csrf_values(**identity), auth=True)[0], 400)
        self.p["admin_operation"].assert_not_called()

    def test_alias_login_and_duplicate_aliases(self):
        values = {"panel_login": "synthetic-admin", "panel_password": "synthetic-password-only", "_login_token": "synthetic"}
        self.assertEqual(self.request("/login", method="POST", values=values,
                                      headers=(("Cookie", "tt_login=synthetic"),))[0], 303)
        values = [("vpn_client_name", "alice"), ("vpn_client_name", "bob"), ("_csrf", self.p["CSRF_TOKEN"])]
        self.assertEqual(self.post(values, auth=True)[0], 400)
        self.p["admin_operation"].assert_not_called()

    def test_post_peer_is_overwritten_by_socket_address(self):
        self.assertEqual(self.post(self.csrf_values(_peer="198.51.100.9"), auth=True,
                                   headers=(("X-Forwarded-For", "192.0.2.9"),))[0], 200)
        self.assertEqual(self.p["admin_operation"].call_args.args[1]["_peer"], "127.0.0.1")

    def test_duplicate_lengths_and_chunked_bodies_are_rejected(self):
        for headers in ((("Transfer-Encoding", "chunked"),),
                        (("Content-Length", "1"), ("Content-Length", "1")),
                        (("Content-Length", "1"), ("Content-Length", "2"))):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("/manage", method="POST", body=b"x", headers=headers, auth=True)[0], 400)
        self.p["admin_operation"].assert_not_called()

    def test_repeated_transfer_encoding_is_rejected_in_every_order(self):
        variants = (("", "chunked"), ("chunked", ""), ("", ""),
                    ("identity", "chunked"), ("chunked", "chunked"))
        for first, second in variants:
            with self.subTest(first=first, second=second):
                headers = (("Transfer-Encoding", first), ("transfer-encoding", second))
                self.assertEqual(self.post(self.csrf_values(), auth=True, headers=headers)[0], 400)
        self.p["admin_operation"].assert_not_called()

    def test_empty_transfer_encoding_is_rejected(self):
        self.assertEqual(self.post(self.csrf_values(), auth=True, headers=(("Transfer-Encoding", ""),))[0], 400)
        self.p["admin_operation"].assert_not_called()

    def test_public_forms_reject_repeated_transfer_encoding_before_authentication(self):
        for path, values, cookie in (
            ("/login", {"username": "synthetic-admin", "password": "synthetic-password-only", "_login_token": "synthetic"},
             "tt_login=synthetic"),
            ("/activate", {"_csrf": "synthetic", "token": "a" * 43}, "tt_activation=synthetic"),
        ):
            with self.subTest(path=path):
                headers = (("Transfer-Encoding", ""), ("Transfer-Encoding", "chunked"),
                           ("Cookie", cookie), ("Origin", "http://panel.example:8088"))
                self.assertEqual(self.request(path, method="POST", values=values, headers=headers)[0], 400)
        self.assertFalse(self.p["SESSIONS"])
        self.p["deeplink"].assert_not_called()

    def test_rejected_framing_does_not_process_a_pipelined_mutation(self):
        headers = (("Transfer-Encoding", ""), ("Transfer-Encoding", "chunked"))
        values = urllib.parse.urlencode(self.csrf_values()).encode()
        pipeline = ("POST /manage HTTP/1.1\r\nHost: panel.example:8088\r\nAuthorization: " + self.auth +
                    "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: " +
                    str(len(values)) + "\r\n\r\n").encode() + values
        status, response_headers, body = self.request("/manage", method="POST", values=self.csrf_values(),
            auth=True, headers=headers, pipeline=pipeline)
        self.assertEqual(status, 400)
        self.p["admin_operation"].assert_not_called()
        self.assertNotIn(b"HTTP/1.", body)

    def test_invalid_utf8_and_percent_encoded_duplicate_identity_are_rejected(self):
        for body in (b"_csrf=\xff", b"vpn_client_name=alice&vpn%5fclient%5fname=bob"):
            self.assertEqual(self.request("/manage", method="POST", body=body, auth=True)[0], 400)
        self.p["admin_operation"].assert_not_called()

    def test_short_huge_negative_and_invalid_lengths_are_rejected(self):
        for length in ("100", "65537", "-1", "invalid"):
            self.assertEqual(self.request("/manage", method="POST", body=b"x",
                                          headers=(("Content-Length", length),), auth=True)[0], 400)
        self.p["admin_operation"].assert_not_called()

    def test_duplicate_fields_excess_fields_and_wrong_content_type_are_rejected(self):
        for body in (b"action=monitor&action=system-reboot", b"&".join(b"f%d=x" % n for n in range(81))):
            self.assertEqual(self.request("/manage", method="POST", body=body, auth=True)[0], 400)
        for mime in ("application/json", "text/plain"):
            self.assertEqual(self.request("/manage", method="POST", body=b"{}", auth=True,
                                          headers=(("Content-Type", mime),))[0], 400)
        self.p["admin_operation"].assert_not_called()

    def test_public_malformed_requests_cannot_render_private_error_page(self):
        for path in ("/activate", "/login"):
            for length in ("invalid", "4097"):
                status, headers, body = self.request(path, method="POST", body=b"x",
                    headers=(("Content-Length", length), ("Origin", "http://panel.example:8088")))
                self.assertEqual(status, 400)
                self.assertNotIn(b"synthetic-private-dashboard", body)
                self.assertNotIn(self.p["CSRF_TOKEN"].encode(), body)
        self.p["html_page"].assert_not_called()

    def test_http10_response_closes_before_pipelined_request(self):
        pipeline = b"GET / HTTP/1.1\r\nHost: panel.example:8088\r\n\r\n"
        status, headers, body = self.request("/health", pipeline=pipeline)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok\n")
        self.assertEqual(self.handler.protocol_version, "HTTP/1.0")
        self.p["html_page"].assert_not_called()

    def test_trickled_request_headers_have_an_absolute_deadline(self):
        self.assert_read_deadline(SlowMemoryConnection)

    def test_slow_header_field_cannot_extend_the_read_deadline(self):
        self.assert_read_deadline(SlowHeaderConnection)

    def test_slow_form_body_cannot_extend_the_read_deadline(self):
        self.assert_read_deadline(SlowBodyConnection, "/manage", method="POST", values=self.csrf_values(), auth=True)

    def test_public_login_body_has_a_total_read_deadline(self):
        self.assert_read_deadline(SlowBodyConnection, "/login", method="POST", values={
            "panel_login": "synthetic-admin", "panel_password": "synthetic-password-only", "_login_token": "synthetic",
        }, headers=(("Cookie", "tt_login=synthetic"), ("Origin", "http://panel.example:8088")))

    def test_headers_and_body_share_one_total_read_budget(self):
        self.assert_read_deadline(SharedReadBudgetConnection, "/manage", method="POST", values=self.csrf_values(), auth=True)

    def test_global_connection_budget_is_bounded_and_released(self):
        server = self.memory_server()
        connections = [object() for index in range(16)]
        with patch.object(http.server.ThreadingHTTPServer, "process_request") as dispatch:
            for index, connection in enumerate(connections):
                server.process_request(connection, ("198.51.100." + str(index + 1), index))
            self.assertEqual(dispatch.call_count, 16)
            server.process_request(object(), ("203.0.113.1", 9999))
            self.assertEqual(dispatch.call_count, 16)
            server.shutdown_request.assert_called_once()
            with patch.object(http.server.ThreadingHTTPServer, "process_request_thread"):
                server.process_request_thread(connections[0], ("198.51.100.1", 0))
            server.process_request(object(), ("203.0.113.1", 9999))
            self.assertEqual(dispatch.call_count, 17)

    def test_per_peer_admission_leaves_capacity_for_another_peer(self):
        server = self.memory_server()
        with patch.object(http.server.ThreadingHTTPServer, "process_request") as dispatch:
            for index in range(16):
                server.process_request(object(), ("198.51.100.1", index))
            admitted = dispatch.call_count
            self.assertEqual(admitted, PER_PEER_CONNECTIONS, "Per-peer admission limit must remain four")
            self.assertEqual(server.shutdown_request.call_count, 16 - admitted)
            server.process_request(object(), ("203.0.113.1", 9999))
            self.assertEqual(dispatch.call_count, admitted + 1)

    def test_per_peer_capacity_is_released_after_worker_completion(self):
        server = self.memory_server()
        with patch.object(http.server.ThreadingHTTPServer, "process_request") as dispatch:
            for index in range(16):
                server.process_request(object(), ("198.51.100.1", index))
            admitted = dispatch.call_count
            self.assertEqual(admitted, PER_PEER_CONNECTIONS)
            connection, peer = dispatch.call_args_list[0].args
            with patch.object(http.server.ThreadingHTTPServer, "process_request_thread"):
                server.process_request_thread(connection, peer)
            server.process_request(object(), ("198.51.100.1", 9999))
            self.assertEqual(dispatch.call_count, admitted + 1)

    def test_per_peer_rejections_do_not_consume_global_capacity(self):
        server = self.memory_server()
        with patch.object(http.server.ThreadingHTTPServer, "process_request") as dispatch:
            for index in range(24):
                server.process_request(object(), ("198.51.100.1", index))
            self.assertEqual(dispatch.call_count, PER_PEER_CONNECTIONS)
            for host in ("198.51.100.2", "198.51.100.3", "198.51.100.4"):
                for index in range(PER_PEER_CONNECTIONS):
                    server.process_request(object(), (host, index))
            self.assertEqual(dispatch.call_count, 16)

    def test_global_rejection_does_not_consume_rejected_peer_capacity(self):
        server = self.memory_server()
        with patch.object(http.server.ThreadingHTTPServer, "process_request") as dispatch:
            for index in range(16):
                server.process_request(object(), ("198.51.100." + str(index + 1), index))
            server.process_request(object(), ("203.0.113.1", 9999))
            self.assertEqual(dispatch.call_count, 16)
            with patch.object(http.server.ThreadingHTTPServer, "process_request_thread"):
                for call in dispatch.call_args_list[:PER_PEER_CONNECTIONS]:
                    server.process_request_thread(*call.args)
            for index in range(PER_PEER_CONNECTIONS):
                server.process_request(object(), ("203.0.113.1", index))
            self.assertEqual(dispatch.call_count, 16 + PER_PEER_CONNECTIONS)

    def test_worker_exception_releases_global_and_per_peer_capacity(self):
        server = self.memory_server()
        with patch.object(http.server.ThreadingHTTPServer, "process_request") as dispatch:
            for index in range(PER_PEER_CONNECTIONS):
                server.process_request(object(), ("198.51.100.1", index))
            connection, peer = dispatch.call_args_list[0].args
            with patch.object(http.server.ThreadingHTTPServer, "process_request_thread", side_effect=RuntimeError("synthetic worker failure")):
                with self.assertRaisesRegex(RuntimeError, "synthetic worker failure"):
                    server.process_request_thread(connection, peer)
            server.process_request(object(), ("198.51.100.1", 9999))
            self.assertEqual(dispatch.call_count, PER_PEER_CONNECTIONS + 1)

    def test_dispatch_failure_does_not_leak_global_or_per_peer_capacity(self):
        server = self.memory_server()
        with patch.object(http.server.ThreadingHTTPServer, "process_request", side_effect=RuntimeError("synthetic dispatch failure")):
            for index in range(20):
                with self.assertRaisesRegex(RuntimeError, "synthetic dispatch failure"):
                    server.process_request(object(), ("198.51.100.1", index))
        with patch.object(http.server.ThreadingHTTPServer, "process_request") as dispatch:
            server.process_request(object(), ("198.51.100.1", 9999))
            dispatch.assert_called_once()

    def test_activation_requires_origin_csrf_and_remote_tls(self):
        self.assertEqual(self.request("/activate", method="POST", values={})[0], 403)
        headers = (("Origin", "http://panel.example:8088"), ("Cookie", "tt_activation=synthetic"))
        self.assertEqual(self.request("/activate", method="POST", values={"_csrf": "wrong"}, headers=headers)[0], 403)
        self.assertEqual(self.request("/activate", method="POST", values={"_csrf": "synthetic"},
                                      headers=headers, peer="198.51.100.1")[0], 403)

    def test_activation_does_not_accept_forged_forwarded_peer(self):
        self.p["redeem_enrollment"] = Mock(return_value={"link": "tt://?synthetic"})
        headers = (("Origin", "http://panel.example:8088"), ("Cookie", "tt_activation=synthetic"),
                   ("X-Forwarded-For", "198.51.100.2"))
        self.assertEqual(self.request("/activate", method="POST", values={"_csrf": "synthetic", "token": "a" * 43},
                                      headers=headers)[0], 200)
        self.p["redeem_enrollment"].assert_called_once_with("a" * 43, "127.0.0.1")

    def test_backup_download_is_authenticated_and_uncacheable(self):
        self.files["/root/trusttunnel-identity-backup.zip"] = b"synthetic-backup-secret"
        self.assertEqual(self.request("/backup/latest.zip")[0], 401)
        status, headers, body = self.request("/backup/latest.zip", auth=True)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"synthetic-backup-secret")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("attachment", headers["Content-Disposition"])

    def test_profile_download_requires_active_client_and_rejects_traversal(self):
        self.files["/root/trusttunnel-clients/alice-http2.toml"] = b"synthetic-profile-secret"
        for path in ("/client/%2e%2e%2fetc/http2.toml", "/client/%2fetc/http2.toml", "/client/disabled/http2.toml"):
            self.assertEqual(self.request(path, auth=True)[0], 404)
        status, headers, body = self.request("/client/alice/http2.toml", auth=True)
        self.assertEqual(status, 200)
        self.assertEqual(body, b"synthetic-profile-secret")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_backup_archive_excludes_unlisted_secrets_and_symlinks(self):
        root = "/root/trusttunnel-identity-backup/"
        for item in ("certs/key.pem", "credentials.toml", "panel.env", "usage.sqlite3",
                     "client-files/alice.toml", "client-files/leak.symlink"):
            self.files[root + item] = b"synthetic"
        self.p["installer_operation"] = Mock()
        archive = Mock()
        self.p["zipfile"].ZipFile.return_value.__enter__ = Mock(return_value=archive)
        self.p["zipfile"].ZipFile.return_value.__exit__ = Mock(return_value=False)
        self.p["backup_archive"]()
        written = {call.args[1] for call in archive.write.call_args_list}
        self.assertEqual(written, {"certs/key.pem", "credentials.toml", "client-files/alice.toml"})

    def test_firewall_argument_allowlists(self):
        bad = ({"decision": "--force"}, {"direction": "in; reboot"}, {"proto": "all"},
               {"port": "80;reboot"}, {"port": "1:65536"}, {"interface": "--help"},
               {"source": "any --force"}, {"comment": "x\nufw disable"}, {"comment": "x'y"})
        for change in bad:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.p["firewall_rule"]({"port": "12345", **change})
        self.p["run"].assert_not_called()
        self.p["checked_run"].assert_not_called()

    def test_firewall_validated_values_stay_in_individual_arguments(self):
        result = self.p["firewall_rule"]({"port": "12345", "source": "198.51.100.0/24", "comment": "review test"})
        self.assertEqual(result, ["ufw", "allow", "in", "proto", "tcp", "from", "198.51.100.0/24",
                                  "to", "any", "port", "12345", "comment", "review test"])

    def test_log_unit_allowlist_and_bounded_line_count(self):
        with self.assertRaises(ValueError):
            self.p["recent_logs"]("--file=/synthetic-secret")
        self.p["recent_logs"]("trusttunnel", 100000)
        self.assertEqual(self.p["run"].call_args.args[0], ["journalctl", "-u", "trusttunnel", "--no-pager", "-n", "500"])

    def test_fail2ban_rejects_unknown_jails_and_protected_addresses(self):
        with self.assertRaises(ValueError):
            self.p["jail_name"]({"jail": "--help"})
        with self.assertRaises(ValueError):
            self.p["jail_name"]({"jail": "unconfigured"})
        for ip in ("127.0.0.1", "::ffff:127.0.0.1", "198.51.100.1"):
            with self.assertRaises(ValueError):
                self.p["fail2ban_operation"]("ban", {"ip": ip, "_peer": "198.51.100.1", "confirm": "CONFIRMED"})
        self.p["checked_run"].assert_not_called()

    def test_installer_action_channel_and_confirmation_allowlists(self):
        for action, values in (("remove-all", {}), ("install", {}), ("remove-warp", {}),
                               ("reregister-warp", {}), ("update-trusttunnel", {"channel": "nightly"}),
                               ("update-trusttunnel", {"channel": "beta"}),
                               ("switch-certificate-mode", {"cert_mode": "self-signed"})):
            with self.subTest(action=action, values=values), self.assertRaises(ValueError):
                self.p["installer_operation"](action, values)
        self.p["run"].assert_not_called()

    def test_approved_installer_call_has_fixed_argv_and_synthetic_environment(self):
        self.p["installer_operation"]("update-trusttunnel", {"channel": "beta", "beta_confirm": "BETA"})
        call = self.p["run"].call_args
        self.assertEqual(call.args[0], ["/bin/bash", "/usr/local/sbin/trusttunnel-menu"])
        self.assertEqual(call.kwargs["env"], {"ACTION": "update-trusttunnel", "AUTO_CONFIRM": "1", "TT_CHANNEL": "beta"})
        self.assertEqual(call.kwargs["input_text"], "")

    def test_reboot_requires_typed_confirmation(self):
        with self.assertRaises(ValueError):
            self.p["power_operation"]("system-reboot", {})
        self.p["checked_run"].assert_not_called()

    def test_diagnostic_target_allowlist(self):
        with self.assertRaises(ValueError):
            self.p["diagnostic_report"]("egress", {"target": "file:///synthetic-secret"})
        self.p["run"].assert_not_called()

    def test_public_non_tls_listener_is_rejected_before_socket_creation(self):
        self.p["os"].environ.update(PANEL_BIND="0.0.0.0")
        self.p["PanelServer"] = Mock()
        with self.assertRaises(RuntimeError):
            self.p["main"]()
        self.p["PanelServer"].assert_not_called()

    def test_scanner_protection_requires_confirmation_before_mutation(self):
        for action in ("prepare", "enforce", "tls-prepare", "tls-enforce", "disable"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.p["protection_operation"](action, {})
        self.p["atomic_write"].assert_not_called()
        self.p["commit_protection_rules"].assert_not_called()
        self.p["run"].assert_not_called()

    def test_official_prefix_enforcement_is_blocked_with_quic(self):
        self.p["quic_enabled"].return_value = True
        self.p["protection_state"].return_value = {"prefix": "0011223344556677"}
        with self.assertRaises(ValueError):
            self.p["protection_operation"]("enforce", {"confirm": "CONFIRMED", "clients_ready": "1"})
        self.p["commit_protection_rules"].assert_not_called()
        self.p["atomic_write"].assert_not_called()

    def test_tls_auth_cannot_be_enforced_on_unsupported_official_endpoint(self):
        with self.assertRaises(ValueError):
            self.p["protection_operation"]("tls-enforce", {"confirm": "CONFIRMED", "clients_ready": "1", "client_v13": "1"})
        self.p["commit_protection_rules"].assert_not_called()
        self.p["atomic_write"].assert_not_called()

    def test_tls_auth_enforcement_is_blocked_with_quic(self):
        self.p["endpoint_capabilities"].return_value = {"prefix": True, "auth_key": True}
        self.p["quic_enabled"].return_value = True
        with self.assertRaises(ValueError):
            self.p["protection_operation"]("tls-enforce", {"confirm": "CONFIRMED", "clients_ready": "1", "client_v13": "1"})
        self.p["commit_protection_rules"].assert_not_called()

    def test_strict_scanner_protection_blocks_installer_replacement(self):
        self.p["strict_protection_locked"].return_value = True
        for action in ("install", "update-trusttunnel"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.p["installer_operation"](action, {"confirm": "REINSTALL"})
        self.p["run"].assert_not_called()

    def test_passive_scanner_counters_do_not_run_commands(self):
        for kind in ("failures", "rejected", "throttled", "unrecognized"):
            self.p["panel_event"](kind)
        self.assertEqual(len(self.p["PANEL_EVENTS"]), 1)
        counts = next(iter(self.p["PANEL_EVENTS"].values()))
        self.assertEqual({key: counts[key] for key in ("failures", "rejected", "throttled")},
                         {"failures": 1, "rejected": 1, "throttled": 1})
        self.p["run"].assert_not_called()
        self.p["checked_run"].assert_not_called()
        self.p["atomic_write"].assert_not_called()

    def test_rejected_interface_reregistration_has_no_service_side_effects(self):
        with self.assertRaises(ValueError):
            self.p["interface_operation"]("reregister", {"transport": "wireguard"})
        self.assertEqual(self.p["run"].call_args_list, [], "Rejected registration stopped services")
        self.p["checked_run"].assert_not_called()
        self.p["atomic_write"].assert_not_called()

    def test_rejected_interface_install_has_no_service_side_effects(self):
        with self.assertRaises(ValueError):
            self.p["interface_operation"]("install", {"transport": "wireguard"})
        self.assertEqual(self.p["run"].call_args_list, [], "Rejected installation stopped services")
        self.p["checked_run"].assert_not_called()
        self.p["atomic_write"].assert_not_called()

    def test_missing_interface_tool_has_no_service_side_effects(self):
        with self.assertRaises(ValueError):
            self.p["interface_operation"]("install", {"transport": "wireguard", "accept_tos": "1", "confirm": "CONFIRMED"})
        self.p["run"].assert_not_called()
        self.p["checked_run"].assert_not_called()
        self.p["atomic_write"].assert_not_called()

    def enrollment_db(self, source="", identity="synthetic-identity"):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE enrollment (digest TEXT PRIMARY KEY, username TEXT, protocol TEXT,
                kind TEXT, identity TEXT, expires REAL, consumed INTEGER);
            CREATE TABLE enrollment_sources (digest TEXT PRIMARY KEY, source_cidr TEXT);
        """)
        token = "a" * 43
        digest = hashlib.sha256(token.encode()).hexdigest()
        db.execute("INSERT INTO enrollment VALUES (?,?,?,?,?,?,0)",
                   (digest, "alice", "http2", "static", identity, time.time() + 60))
        if source:
            db.execute("INSERT INTO enrollment_sources VALUES (?,?)", (digest, source))
        db.commit()
        self.p["usage_database"] = lambda: db
        self.p["canonical_ip"] = ipaddress.ip_address
        return db, token

    def test_enrollment_token_can_only_be_consumed_once(self):
        db, token = self.enrollment_db()
        self.assertEqual(self.p["redeem_enrollment"](token, "127.0.0.1")["link"], "tt://?synthetic")
        with self.assertRaises(ValueError):
            self.p["redeem_enrollment"](token, "127.0.0.1")
        self.assertEqual(db.execute("SELECT consumed FROM enrollment").fetchone()[0], 1)
        self.p["deeplink"].assert_called_once()

    def test_enrollment_source_and_identity_are_checked_before_export(self):
        db, token = self.enrollment_db(source="198.51.100.0/24")
        with self.assertRaises(ValueError):
            self.p["redeem_enrollment"](token, "203.0.113.1")
        self.assertEqual(db.execute("SELECT consumed FROM enrollment").fetchone()[0], 0)
        self.p["deeplink"].assert_not_called()
        db.execute("UPDATE enrollment SET identity='changed'")
        db.commit()
        with self.assertRaises(ValueError):
            self.p["redeem_enrollment"](token, "198.51.100.1")
        self.p["deeplink"].assert_not_called()


class InstallerSourceTests(unittest.TestCase):
    @staticmethod
    def restrictive_creation_guard(text):
        preamble = INSTALLER_SOURCE.split("need_root() {", 1)[0]
        return bool(re.search(r"(?m)^\s*umask\s+0?077\s*(?:#.*)?$", preamble + text))

    def test_new_panel_environment_is_private_before_first_secret_write(self):
        function = shell_function("install_panel")
        before_secret_write = function.split('cat > "$env_file"', 1)[0]
        protected = self.restrictive_creation_guard(before_secret_write)
        protected |= bool(re.search(r'(?:install\s+-m\s+0?600|chmod\s+0?600).*\$env_file', before_secret_write))
        self.assertTrue(protected, "No restrictive creation guard precedes the panel password write")

    def test_new_client_credentials_are_private_before_first_secret_write(self):
        function = shell_function("write_clients")
        before_secret_write = function.split('cat > "$TT_DIR/credentials.toml"', 1)[0]
        protected = self.restrictive_creation_guard(before_secret_write)
        protected |= bool(re.search(r'(?:install\s+-m\s+0?600|chmod\s+0?600).*credentials\.toml', before_secret_write))
        self.assertTrue(protected, "No restrictive creation guard precedes the VPN credentials write")

    def test_mode_model_for_documented_direct_install_condition(self):
        self.assertEqual(0o666 & ~0o022, 0o644)
        self.assertEqual(0o777 & ~0o022, 0o755)
        self.assertEqual(0o666 & ~0o077, 0o600)

    def test_direct_installer_and_generated_menu_use_private_umask(self):
        preamble = INSTALLER_SOURCE.split("need_root() {", 1)[0]
        self.assertRegex(preamble, r"(?m)^\s*umask\s+0?077\s*(?:#.*)?$")
        self.assertRegex(shell_function("write_tools"), r"(?m)^\s*umask\s+0?077\s*(?:#.*)?$")

    def test_panel_service_has_restrictive_umask(self):
        self.assertIn("UMask=0077", shell_function("install_panel"))

    def test_identity_restore_metadata_is_not_sourced_as_shell(self):
        self.assertNotRegex(shell_function("restore_identity"), r'(?m)^\s*(?:source|\.)\s+.*identity\.env')


class ForbiddenRealOperation(RuntimeError):
    pass


class SyntheticResult(unittest.TextTestResult):
    def _exc_info_to_string(self, err, test):
        error_type, error, traceback = err
        frames = []
        while traceback is not None:
            code = traceback.tb_frame.f_code
            frames.append("  %s:%s in %s" % (code.co_filename, traceback.tb_lineno, code.co_name))
            traceback = traceback.tb_next
        return "\n".join(frames + [error_type.__name__ + ": " + str(error)]) + "\n"


def enforce_synthetic_only(event, args):
    if event == "open":
        name, mode, flags = args
        if not isinstance(name, str) or mode is None or any(letter in mode for letter in "wax+"):
            raise ForbiddenRealOperation("Real filesystem write or descriptor access blocked")
        allowed = {str(PANEL_PATH).casefold(), str(INSTALLER_PATH).casefold(), str(Path(__file__).resolve()).casefold()}
        if str(Path(name).resolve()).casefold() not in allowed:
            raise ForbiddenRealOperation("Non-review file read blocked")
    if event.startswith(("subprocess.", "socket.", "shutil.")) or event in {
        "os.system", "os.mkdir", "os.remove", "os.rename", "os.rmdir", "os.chmod",
        "os.chown", "os.link", "os.symlink", "os.truncate", "os.utime", "os.startfile",
    } or event.startswith(("os.exec", "os.spawn")):
        raise ForbiddenRealOperation("Real filesystem, service, or network mutation blocked: " + event)
    if event == "sqlite3.connect" and args[0] != ":memory:":
        raise ForbiddenRealOperation("Only an in-memory database is permitted")


if __name__ == "__main__":
    print("Synthetic review only; no real credentials, services, files, or sockets are used.")
    print("Panel SHA256:", hashlib.sha256(PANEL_BYTES).hexdigest(), flush=True)
    print("Installer SHA256:", hashlib.sha256(INSTALLER_BYTES).hexdigest(), flush=True)
    anchors = {node.name: node.lineno for node in REVIEW_TREE.body
               if node.name in ("Handler", "PanelServer", "interface_operation", "panel_event")}
    anchors.update({"Handler." + node.name: node.lineno for parent in REVIEW_TREE.body
                    if isinstance(parent, ast.ClassDef) and parent.name == "Handler"
                    for node in parent.body if isinstance(node, ast.FunctionDef)
                    and node.name in ("setup", "form", "handle_login", "handle_activation", "handle_post")})
    print("Reviewed snapshot line anchors:", json.dumps(anchors, sort_keys=True), flush=True)
    sys.addaudithook(enforce_synthetic_only)
    unittest.main(testRunner=unittest.TextTestRunner(verbosity=2, resultclass=SyntheticResult))
