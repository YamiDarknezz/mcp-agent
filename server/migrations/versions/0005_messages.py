"""Persist encrypted channel messages."""

from alembic import op
from server.settings import runtime_db_role

revision = "0005_messages"
down_revision = "0004_encryption"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE channel_messages (
            channel_id uuid NOT NULL REFERENCES channels(id),
            seq bigint NOT NULL CHECK (seq > 0),
            operation_id uuid NOT NULL,
            device_id uuid NOT NULL REFERENCES devices(id),
            nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
            ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 4112),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (channel_id, seq),
            UNIQUE (device_id, operation_id)
        )
    """)
    if role := runtime_db_role():
        quoted = op.get_bind().dialect.identifier_preparer.quote_identifier(role)
        op.execute(f"GRANT SELECT, INSERT ON channel_messages TO {quoted}")


def downgrade() -> None:
    op.drop_table("channel_messages")
