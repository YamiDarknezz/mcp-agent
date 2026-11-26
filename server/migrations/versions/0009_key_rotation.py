"""Track retired channel keys so old material stays readable but unusable for sending."""

from alembic import op
from server.settings import runtime_db_role

revision = "0009_key_rotation"
down_revision = "0008_channel_invites"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE channel_keys
            ADD COLUMN rotated_at timestamptz,
            ADD COLUMN rotation_required boolean NOT NULL DEFAULT false
    """)
    op.execute("""
        CREATE TABLE channel_key_history (
            channel_id uuid NOT NULL REFERENCES channels(id),
            key_id uuid NOT NULL,
            retired_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (channel_id, key_id)
        )
    """)
    if role := runtime_db_role():
        quoted = op.get_bind().dialect.identifier_preparer.quote_identifier(role)
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON channel_keys, channel_key_history TO {quoted}")


def downgrade() -> None:
    op.drop_table("channel_key_history")
    op.execute("ALTER TABLE channel_keys DROP COLUMN rotation_required")
    op.execute("ALTER TABLE channel_keys DROP COLUMN rotated_at")
