import unittest

from client.relay_version import CLIENT_VERSION, PROTOCOL_VERSION, is_older, warning


class VersionTests(unittest.TestCase):
    def test_markers_are_present(self):
        self.assertTrue(CLIENT_VERSION)
        self.assertIsInstance(PROTOCOL_VERSION, int)

    def test_older_versions_are_detected(self):
        self.assertTrue(is_older("0.1.0", CLIENT_VERSION))
        self.assertFalse(is_older(CLIENT_VERSION, CLIENT_VERSION))
        self.assertFalse(is_older("999.0.0", CLIENT_VERSION))
        self.assertFalse(is_older("no-version", CLIENT_VERSION))

    def test_warning_is_actionable_only_for_older_clients(self):
        self.assertIn("0.1.0", warning("0.1.0"))
        self.assertIsNone(warning(CLIENT_VERSION))


if __name__ == "__main__":
    unittest.main()
