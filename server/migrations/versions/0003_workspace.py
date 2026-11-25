"""Persist project roots, subchannels, scoped roles and subscriptions."""

from alembic import op

from server.settings import runtime_db_role

revision = "0003_workspace"
down_revision = "0002_activation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE channels (
            id uuid PRIMARY KEY,
            project_id uuid NOT NULL,
            parent_id uuid,
            kind text NOT NULL CHECK (kind IN ('project', 'main', 'work')),
            parent_kind text,
            depth integer NOT NULL CHECK (depth BETWEEN 0 AND 8),
            parent_depth integer,
            name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 100),
            slug text NOT NULL CHECK (char_length(slug) <= 64 AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
            inherits_access boolean NOT NULL,
            created_by uuid NOT NULL REFERENCES users(id),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            -- parent_depth is the parent's depth (0 for root, 1 for main, ...).
            -- The composite FK below validates it against the referenced row.
            CHECK ((parent_id IS NULL AND parent_kind IS NULL AND parent_depth IS NULL)
                   OR (parent_id IS NOT NULL AND parent_kind IS NOT NULL AND parent_depth IS NOT NULL)),
            UNIQUE (project_id, id, kind, depth),
            FOREIGN KEY (project_id, parent_id, parent_kind, parent_depth)
                REFERENCES channels (project_id, id, kind, depth),
            CHECK ((
                (kind = 'project' AND id = project_id AND parent_id IS NULL
                    AND parent_kind IS NULL AND depth = 0 AND NOT inherits_access)
                OR (kind = 'main' AND id <> project_id AND parent_id = project_id
                    AND parent_kind = 'project' AND depth = 1
                    AND name = 'main' AND slug = 'main' AND inherits_access)
                OR (kind = 'work' AND id <> project_id AND parent_id IS NOT NULL
                    AND parent_kind IN ('project', 'work') AND depth > 0
                    AND (parent_id <> project_id OR slug <> 'main'))
            ) IS TRUE)
        )
    """)
    op.execute("CREATE UNIQUE INDEX channel_root_slug ON channels (created_by, slug) WHERE kind = 'project'")
    op.execute("CREATE UNIQUE INDEX channel_sibling_slug ON channels (parent_id, slug) WHERE parent_id IS NOT NULL")
    op.execute("CREATE UNIQUE INDEX channel_one_main ON channels (project_id) WHERE kind = 'main'")
    op.execute("""
        CREATE TABLE channel_memberships (
            channel_id uuid NOT NULL REFERENCES channels(id),
            user_id uuid NOT NULL REFERENCES users(id),
            role text CHECK (role IN ('reader', 'collaborator', 'admin', 'owner')),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (channel_id, user_id)
        )
    """)
    op.execute("CREATE INDEX membership_by_user ON channel_memberships (user_id, channel_id)")
    op.execute("""
        CREATE TABLE channel_subscriptions (
            channel_id uuid NOT NULL REFERENCES channels(id),
            user_id uuid NOT NULL REFERENCES users(id),
            mode text NOT NULL CHECK (mode IN ('all', 'mentions', 'muted')),
            PRIMARY KEY (channel_id, user_id)
        )
    """)

    if role := runtime_db_role():
        quoted = op.get_bind().dialect.identifier_preparer.quote_identifier(role)
        op.execute(f"GRANT SELECT, INSERT ON channels, channel_memberships, channel_subscriptions TO {quoted}")


def downgrade() -> None:
    for table in ("channel_subscriptions", "channel_memberships", "channels"):
        op.drop_table(table)
