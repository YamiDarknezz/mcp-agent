from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
import unittest

from client.relay_identity import DeviceVault, IdentityError
from client.relay_mcp import _probe, server_origin


@contextmanager
def fake_http(routes):
    visited = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            visited.append(self.path)
            status, headers, body = routes[self.path]
            self.send_response(status)
            for name, value in headers.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", visited
        finally:
            server.shutdown()
            thread.join()


class RelayProbeTests(unittest.TestCase):
    def test_accepts_reusable_https_or_local_http(self):
        self.assertEqual(server_origin("https://agents.example.com/"), "https://agents.example.com")
        self.assertEqual(server_origin("http://127.0.0.1:8765"), "http://127.0.0.1:8765")
        self.assertEqual(server_origin("http://[::1]:8765"), "http://[::1]:8765")

    def test_refuses_credentials_paths_and_insecure_remote_http(self):
        for url in (
            None,
            "https://user:password@example.com",
            "https://example.com/ready",
            "https://example.com?key=example",
            "https://example.com#invite",
            "http://example.com",
            "https://example.com\\other",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                server_origin(url)

    def test_reports_only_expected_status(self):
        with fake_http({"/health": (200, {}, b'{"status":"ok","extra":"ignored"}')}) as (url, _):
            self.assertTrue(_probe(url, "health", "ok"))
            self.assertFalse(_probe(url, "health", "ready"))

    def test_does_not_follow_redirects(self):
        routes = {
            "/ready": (302, {"Location": "/other"}, b""),
            "/other": (200, {}, b'{"status":"ready"}'),
        }
        with fake_http(routes) as (url, visited):
            self.assertFalse(_probe(url, "ready", "ready"))
            self.assertEqual(visited, ["/ready"])

    def test_oversize_or_error_response_is_not_ready(self):
        routes = {
            "/health": (200, {}, b'{"status":"ok"}' + b" " * 1024),
            "/ready": (503, {}, b'{"status":"ready"}'),
        }
        with fake_http(routes) as (url, _):
            self.assertFalse(_probe(url, "health", "ok"))
            self.assertFalse(_probe(url, "ready", "ready"))


class MemoryVault:
    def __init__(self):
        self.entries = {}

    def get_password(self, service, username):
        return self.entries.get((service, username))

    def set_password(self, service, username, value):
        self.entries[service, username] = value


class DeviceVaultTests(unittest.TestCase):
    def test_preserves_key_across_retries_and_separates_instances(self):
        backend = MemoryVault()
        first = DeviceVault("https://first.example.com", backend)
        second = DeviceVault("https://second.example.com", backend)
        key = first.load_or_create()
        self.assertEqual(first.load_or_create().device_id, key.device_id)
        self.assertEqual(first.load().private.public_key().public_bytes_raw(), key.private.public_key().public_bytes_raw())
        self.assertIsNone(second.load())

    def test_vault_failure_never_falls_back_to_a_file_or_echoes_input(self):
        class Broken(MemoryVault):
            def set_password(self, service, username, value):
                raise RuntimeError("unexpected credential sentinel")

        failing = DeviceVault("https://example.com", Broken())
        with self.assertRaises(IdentityError) as raised:
            failing.load_or_create()
        self.assertNotIn("sentinel", str(raised.exception))
