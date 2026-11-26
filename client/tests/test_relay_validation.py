import unittest

from client.relay_validation import channel_error, choice_error, limit_error, page_error


class ValidationTests(unittest.TestCase):
    def test_page_error_says_what_to_fix(self):
        problem = page_error("read_messages", -1, 20)
        self.assertIn("after", problem["error"])
        self.assertIn("after=0", problem["error"])
        self.assertIn("limit=10", problem["error"])
        self.assertIsNone(page_error("read_messages", 0, 10))

    def test_limit_error_suggests_a_valid_value(self):
        problem = limit_error("list_projects", 0)
        self.assertIn("1 y 100", problem["error"])
        self.assertIn("limit=100", problem["error"])

    def test_choice_error_lists_allowed_values(self):
        problem = choice_error("create_subchannel", "access", "public", {"inherit", "restricted"})
        self.assertIn("inherit", problem["error"])
        self.assertIn("restricted", problem["error"])

    def test_channel_error_points_to_discovery_tools(self):
        problem = channel_error("send_message", "  ")
        self.assertIn("list_channels", problem["error"])
        self.assertIsNone(channel_error("send_message", "channel-1"))


if __name__ == "__main__":
    unittest.main()
