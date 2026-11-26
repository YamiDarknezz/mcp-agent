"""Persist one-time channel invitations with revocation and attempt limits."""

from alembic import op
from server.settings import runtime_db_role

revision = "0008_channel_invites"
down_revision = "0007_tasks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE channel_invites (
            id uuid PRIMARY KEY,
            channel_id uuid NOT NULL REFERENCES channels(id),
            digest bytea NOT NULL UNIQUE,
            invited_role text NOT NULL CHECK (invited_role IN ('reader', 'collaborator', 'admin')),
            issuer_user_id uuid NOT NULL REFERENCES users(id),
            expires_at timestamptz NOT NULL,
            attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
            max_attempts integer NOT NULL DEFAULT 5 CHECK (max_attempts > 0),
            consumed_at timestamptz,
            revoked_at timestamptz,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp()
        )
    """)
    op.execute("CREATE INDEX invites_channel ON channel_invites (channel_id, expires_at)")
    if role := runtime_db_role():
        quoted = op.get_bind().dialect.identifier_preparer.quote_identifier(role)
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON channel_invites TO {quoted}")


def downgrade() -> None:
    op.drop_table("channel_invites")
