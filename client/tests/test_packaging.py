import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PackagingTests(unittest.TestCase):
    def test_pyproject_matches_client_requirements_and_exposes_scripts(self):
        with (ROOT / "pyproject.toml").open("rb") as stream:
            config = tomllib.load(stream)
        expected = {
            line.strip()
            for line in (ROOT / "client" / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        self.assertEqual(set(config["project"]["dependencies"]), expected)
        self.assertEqual(
            config["project"]["scripts"],
            {"relayctl": "client.relayctl:main", "relay-mcp": "client.relay_mcp:main"},
        )

    def test_upgrade_scripts_exist(self):
        for name in ("upgrade_client.ps1", "upgrade_client.sh"):
            self.assertTrue((ROOT / "scripts" / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
