"""Store signed public keys and opaque channel-key envelopes.

The server never holds a channel key, a private key, or plaintext.
"""

from alembic import op

from server.settings import runtime_db_role

revision = "0004_encryption"
down_revision = "0003_workspace"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        ALTER TABLE devices
            ADD COLUMN encryption_public_key bytea
                CHECK (encryption_public_key IS NULL OR octet_length(encryption_public_key) = 32),
            ADD COLUMN encryption_signature bytea
                CHECK (encryption_signature IS NULL OR octet_length(encryption_signature) = 64),
            ADD COLUMN encryption_updated_at timestamptz
    """)
    op.execute("""
        ALTER TABLE devices ADD CONSTRAINT devices_encryption_complete
            CHECK ((encryption_public_key IS NULL) = (encryption_signature IS NULL) AND
                   (encryption_public_key IS NULL) = (encryption_updated_at IS NULL))
    """)
    op.execute("""
        CREATE TABLE channel_keys (
            channel_id uuid PRIMARY KEY REFERENCES channels(id),
            key_id uuid NOT NULL,
            created_by uuid NOT NULL REFERENCES devices(id),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp()
        )
    """)
    op.execute("""
        CREATE TABLE channel_key_envelopes (
            channel_id uuid NOT NULL REFERENCES channel_keys(channel_id) ON DELETE CASCADE,
            recipient_device_id uuid NOT NULL REFERENCES devices(id),
            sender_device_id uuid NOT NULL REFERENCES devices(id),
            envelope bytea NOT NULL CHECK (octet_length(envelope) BETWEEN 80 AND 4096),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            PRIMARY KEY (channel_id, recipient_device_id)
        )
    """)

    if role := runtime_db_role():
        quoted = op.get_bind().dialect.identifier_preparer.quote_identifier(role)
        op.execute(
            f"GRANT UPDATE (encryption_public_key, encryption_signature, encryption_updated_at) "
            f"ON devices TO {quoted}"
        )
        op.execute(f"GRANT SELECT, INSERT ON channel_keys, channel_key_envelopes TO {quoted}")


def downgrade() -> None:
    op.drop_table("channel_key_envelopes")
    op.drop_table("channel_keys")
    op.execute("ALTER TABLE devices DROP CONSTRAINT IF EXISTS devices_encryption_complete")
    op.execute("""
        ALTER TABLE devices
            DROP COLUMN encryption_updated_at,
            DROP COLUMN encryption_signature,
            DROP COLUMN encryption_public_key
    """)
