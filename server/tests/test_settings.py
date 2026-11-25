import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from server.settings import ConfigurationError, database_url, public_url, redis_url


class SettingsTests(unittest.TestCase):
    def test_local_http_and_custom_production_domain(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(public_url(), "http://127.0.0.1:8765")
        with patch.dict(
            os.environ,
            {"MCP_ENV": "production", "MCP_PUBLIC_URL": "https://team.example.net/"},
            clear=True,
        ):
            self.assertEqual(public_url(), "https://team.example.net")

    def test_reject_insecure_or_non_origin_production_urls(self):
        for url in (
            "",
            "http://127.0.0.1",
            "https://agent.example.com/path",
            "https://user:secret@agent.example.com",
            "https://agent.example.com/?code=example",
            "https://agent.example.com/#fragment",
        ):
            with self.subTest(url=url), patch.dict(
                os.environ, {"MCP_ENV": "production", "MCP_PUBLIC_URL": url}, clear=True
            ):
                with self.assertRaisesRegex(ConfigurationError, "HTTPS origin") as error:
                    public_url()
                self.assertNotIn("secret", str(error.exception))

    def test_postgres_url_accepts_escaped_credentials_from_file(self):
        with TemporaryDirectory() as temp:
            path = Path(temp, "db")
            path.write_text("postgresql://worker:test%40value@pg.example.net/app\n", encoding="utf-8")
            with patch.dict(os.environ, {"DATABASE_URL_FILE": str(path)}, clear=True):
                url = database_url()
                self.assertEqual(url.drivername, "postgresql+psycopg")
                self.assertEqual(url.password, "test@value")
                self.assertNotIn("test@value", str(url))

    def test_conflicting_or_invalid_database_inputs_do_not_echo_values(self):
        for env in (
            {"DATABASE_URL": "sentinel-value"},
            {"DATABASE_URL": "sentinel-value", "DATABASE_URL_FILE": "unused"},
            {"DATABASE_URL": "sqlite:///:memory:"},
        ):
            with self.subTest(env=env), patch.dict(os.environ, env, clear=True):
                with self.assertRaises(ConfigurationError) as error:
                    database_url()
                self.assertNotIn("sentinel-value", str(error.exception))

    def test_redis_is_optional_or_configurable_by_file(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(redis_url())
        with TemporaryDirectory() as temp:
            path = Path(temp, "redis")
            path.write_text("rediss://cache.example.net:6379/0\n", encoding="utf-8")
            with patch.dict(os.environ, {"REDIS_URL_FILE": str(path)}, clear=True):
                self.assertEqual(redis_url(), "rediss://cache.example.net:6379/0")
