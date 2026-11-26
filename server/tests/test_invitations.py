import re
import unittest

from server import invitations
from server.identity import Denied


class InvitationCodeTests(unittest.TestCase):
    def test_code_shape_and_digest_are_stable(self):
        code = "relay_inv_" + "a" * 43
        self.assertRegex(code, invitations.CODE_PATTERN)
        self.assertEqual(invitations._digest(code), invitations._digest(code))
        self.assertEqual(len(invitations._digest(code)), 32)

    def test_bad_codes_are_rejected_before_database_access(self):
        for code in ("", "relay_boot_" + "a" * 43, "relay_inv_short", "relay_inv_" + "!" * 43):
            with self.subTest(code=code), self.assertRaises(Denied):
                invitations._digest(code)

    def test_role_constants_and_attempt_limit(self):
        self.assertEqual(invitations.INVITABLE_ROLES, ("reader", "collaborator", "admin"))
        self.assertEqual(invitations.MAX_ATTEMPTS, 5)
        self.assertTrue(re.fullmatch(invitations.KEY_PATTERN, "a" * 43))


if __name__ == "__main__":
    unittest.main()
