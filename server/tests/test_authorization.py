import unittest

from server.authorization import (
    Channel,
    ChannelKind,
    Permission,
    Role,
    allows,
    can_change_membership,
    can_invite,
    effective_role,
)


class EffectiveRoleTests(unittest.TestCase):
    def setUp(self):
        self.channels = {
            "project": Channel("project", ChannelKind.PROJECT),
            "main": Channel("project", ChannelKind.MAIN, "project"),
            "front": Channel("project", ChannelKind.WORK, "project"),
            "screen": Channel("project", ChannelKind.WORK, "front"),
            "back": Channel("project", ChannelKind.WORK, "project"),
            "private": Channel("project", ChannelKind.WORK, "back", False),
            "fix": Channel("project", ChannelKind.WORK, "private"),
        }

    def test_every_inheriting_child_can_use_a_project_grant(self):
        for channel in ("main", "front", "screen", "back"):
            with self.subTest(channel=channel):
                self.assertEqual(
                    effective_role(channel, self.channels, {"project": Role.OWNER}),
                    Role.OWNER,
                )

    def test_direct_grant_does_not_give_access_to_parent_or_siblings(self):
        grants = {"front": Role.COLLABORATOR}
        self.assertEqual(effective_role("screen", self.channels, grants), Role.COLLABORATOR)
        for channel in ("project", "main", "back"):
            with self.subTest(channel=channel):
                self.assertIsNone(effective_role(channel, self.channels, grants))

    def test_restricted_scope_is_hidden_even_from_project_owner(self):
        for channel in ("private", "fix"):
            with self.subTest(channel=channel):
                self.assertIsNone(
                    effective_role(channel, self.channels, {"project": Role.OWNER})
                )

    def test_restricted_scope_can_have_its_own_owner(self):
        grants = {"private": Role.OWNER}
        self.assertEqual(effective_role("private", self.channels, grants), Role.OWNER)
        self.assertEqual(effective_role("fix", self.channels, grants), Role.OWNER)
        self.assertIsNone(effective_role("back", self.channels, grants))

    def test_owner_is_not_a_normal_direct_grant(self):
        for channel in ("front", "main"):
            with self.subTest(channel=channel):
                self.assertIsNone(
                    effective_role(channel, self.channels, {channel: Role.OWNER})
                )

    def test_nearest_grant_can_narrow_an_inherited_role(self):
        grants = {"project": Role.ADMIN, "front": Role.READER}
        self.assertEqual(effective_role("screen", self.channels, grants), Role.READER)
        self.assertEqual(effective_role("back", self.channels, grants), Role.ADMIN)

    def test_scoped_block_does_not_revive_an_inherited_role(self):
        grants = {"project": Role.COLLABORATOR, "front": None}
        self.assertIsNone(effective_role("front", self.channels, grants))
        self.assertIsNone(effective_role("screen", self.channels, grants))
        self.assertEqual(effective_role("back", self.channels, grants), Role.COLLABORATOR)

    def test_direct_grants_are_independent_of_a_block_higher_in_the_tree(self):
        grants = {"project": None, "front": Role.COLLABORATOR}
        self.assertIsNone(effective_role("main", self.channels, grants))
        self.assertEqual(effective_role("screen", self.channels, grants), Role.COLLABORATOR)

    def test_broken_tree_fails_closed_even_with_direct_grant(self):
        self.channels.update(
            {
                "dangling": Channel("project", ChannelKind.WORK, "missing"),
                "other": Channel("other", ChannelKind.PROJECT),
                "cross": Channel("project", ChannelKind.WORK, "other"),
                "cycle-a": Channel("project", ChannelKind.WORK, "cycle-b"),
                "cycle-b": Channel("project", ChannelKind.WORK, "cycle-a"),
                "under-main": Channel("project", ChannelKind.WORK, "main"),
                "private-main": Channel("project", ChannelKind.MAIN, "project", False),
            }
        )
        for channel in ("dangling", "cross", "cycle-a", "under-main", "private-main", "absent"):
            with self.subTest(channel=channel):
                grants = {channel: Role.ADMIN}
                self.assertIsNone(effective_role(channel, self.channels, grants))


class PermissionsTests(unittest.TestCase):
    def test_no_membership_means_no_permissions(self):
        for kind in ChannelKind:
            for permission in Permission:
                with self.subTest(kind=kind, permission=permission):
                    self.assertFalse(allows(None, kind, permission))

    def test_unparsed_values_cannot_bypass_the_policy(self):
        self.assertFalse(allows("admin", ChannelKind.WORK, Permission.SHARE_HISTORY))
        self.assertFalse(allows(Role.READER, ChannelKind.WORK, "download_historical_file"))
        self.assertFalse(can_invite(Role.OWNER, ChannelKind.WORK, "admin"))

    def test_project_root_is_not_a_discussion_channel(self):
        for permission in (
            Permission.SUBSCRIBE,
            Permission.READ_MESSAGES,
            Permission.POST_MESSAGE,
            Permission.PROPOSE_TASK,
            Permission.CLAIM_TASK,
            Permission.UPLOAD_FILE,
            Permission.DOWNLOAD_FILE,
            Permission.SHARE_HISTORY,
        ):
            with self.subTest(permission=permission):
                self.assertFalse(allows(Role.OWNER, ChannelKind.PROJECT, permission))
        self.assertTrue(allows(Role.OWNER, ChannelKind.PROJECT, Permission.CREATE_SUBCHANNEL))

    def test_main_cannot_be_archived_or_have_children(self):
        for permission in (Permission.ARCHIVE_SCOPE, Permission.CREATE_SUBCHANNEL):
            self.assertFalse(allows(Role.OWNER, ChannelKind.MAIN, permission))
        self.assertTrue(allows(Role.COLLABORATOR, ChannelKind.MAIN, Permission.POST_MESSAGE))

    def test_reader_does_not_publish_or_claim(self):
        self.assertTrue(allows(Role.READER, ChannelKind.WORK, Permission.READ_MESSAGES))
        for permission in (
            Permission.POST_MESSAGE,
            Permission.UPLOAD_FILE,
            Permission.PROPOSE_TASK,
            Permission.CLAIM_TASK,
        ):
            with self.subTest(permission=permission):
                self.assertFalse(allows(Role.READER, ChannelKind.WORK, permission))
                self.assertTrue(allows(Role.COLLABORATOR, ChannelKind.WORK, permission))

    def test_only_owner_and_admin_can_share_message_or_file_history(self):
        for role in Role:
            for permission in (Permission.SHARE_HISTORY, Permission.SHARE_HISTORICAL_FILES):
                with self.subTest(role=role, permission=permission):
                    self.assertEqual(
                        allows(role, ChannelKind.WORK, permission),
                        role in (Role.OWNER, Role.ADMIN),
                    )
        self.assertTrue(allows(Role.READER, ChannelKind.WORK, Permission.READ_HISTORY))

    def test_historical_file_download_needs_separate_grant(self):
        for role in Role:
            with self.subTest(role=role):
                self.assertFalse(allows(role, ChannelKind.WORK, Permission.DOWNLOAD_HISTORICAL_FILE))
                self.assertTrue(
                    allows(
                        role,
                        ChannelKind.WORK,
                        Permission.DOWNLOAD_HISTORICAL_FILE,
                        has_historical_file_grant=True,
                    )
                )

    def test_invites_never_assign_ownership_or_escalate(self):
        maximum = {
            Role.READER: set(),
            Role.COLLABORATOR: set(),
            Role.ADMIN: {Role.READER, Role.COLLABORATOR},
            Role.OWNER: {Role.READER, Role.COLLABORATOR, Role.ADMIN},
        }
        for actor, eligible in maximum.items():
            for target in Role:
                with self.subTest(actor=actor, target=target):
                    self.assertEqual(can_invite(actor, ChannelKind.WORK, target), target in eligible)

    def test_admin_can_block_collaborator_but_not_a_peer_or_owner(self):
        for target in (Role.COLLABORATOR, Role.ADMIN, Role.OWNER):
            with self.subTest(target=target):
                self.assertEqual(
                    can_change_membership(
                        Role.ADMIN, ChannelKind.WORK, current_role=target, desired_role=None
                    ),
                    target is Role.COLLABORATOR,
                )

    def test_admin_cannot_use_membership_edits_to_grant_admin(self):
        self.assertFalse(
            can_change_membership(
                Role.ADMIN, ChannelKind.WORK, current_role=Role.READER, desired_role=Role.ADMIN
            )
        )

    def test_owner_can_change_admin_but_cannot_use_ordinary_edits_to_change_owner(self):
        self.assertTrue(
            can_change_membership(
                Role.OWNER, ChannelKind.PROJECT, current_role=Role.ADMIN, desired_role=None
            )
        )
        for current, desired in ((Role.OWNER, None), (Role.READER, Role.OWNER)):
            with self.subTest(current=current, desired=desired):
                self.assertFalse(
                    can_change_membership(
                        Role.OWNER, ChannelKind.PROJECT, current_role=current, desired_role=desired
                    )
                )
