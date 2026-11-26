import unittest
from uuid import uuid4

from client import relay_validation as valid


class ValidationTests(unittest.TestCase):
    def test_limit_has_actionable_message_and_valid_values_pass(self):
        self.assertIsNone(valid.limit(10))
        self.assertIsNone(valid.limit(10, maximum=10))
        for value in (0, 101, 11, "10", True):
            with self.subTest(value=value):
                problem = valid.limit(value, maximum=10)
                self.assertIn("limit", problem["error"])
                self.assertIn("1 y 10", problem["error"])

    def test_after_explains_cursor(self):
        self.assertIsNone(valid.after(0))
        self.assertIsNone(valid.after(42))
        problem = valid.after(-1)
        self.assertIn("after", problem["error"])
        self.assertIn("seq", problem["error"])

    def test_channel_id_explains_where_to_get_it(self):
        self.assertIsNone(valid.channel_id(str(uuid4())))
        for value in ("", "no-uuid", 5, None):
            with self.subTest(value=value):
                problem = valid.channel_id(value)
                self.assertIn("channel_id", problem["error"])
                self.assertIn("list_channels", problem["error"])

    def test_choice_lists_allowed_values(self):
        self.assertIsNone(valid.choice("all", {"all", "muted"}, "mode"))
        problem = valid.choice("other", {"all", "muted"}, "mode")
        self.assertIn("all", problem["error"])
        self.assertIn("muted", problem["error"])


if __name__ == "__main__":
    unittest.main()
