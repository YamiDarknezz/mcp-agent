import subprocess
import sys
import unittest
from pathlib import Path

from client.relayctl import normalize_command

ROOT = Path(__file__).resolve().parents[2]


class CommandAliasTests(unittest.TestCase):
    def test_legacy_names_map_to_canonical_forms(self):
        self.assertEqual(normalize_command("pair"), "pair-start")
        self.assertEqual(normalize_command("join"), "pair-join")
        self.assertEqual(normalize_command("activate"), "activate")
        self.assertEqual(normalize_command("whoami"), "whoami")

    def test_help_exposes_both_canonical_names_and_legacy_aliases(self):
        result = subprocess.run(
            [sys.executable, "-m", "client.relayctl", "--help"],
            cwd=ROOT, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ("pair-start", "pair", "pair-join", "join"):
            self.assertIn(name, result.stdout)


if __name__ == "__main__":
    unittest.main()
