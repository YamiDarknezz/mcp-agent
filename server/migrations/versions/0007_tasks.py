"""Persist encrypted tasks with generation-based reservations."""

from alembic import op
from server.settings import runtime_db_role

revision = "0007_tasks"
down_revision = "0006_subscription_permissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE tasks (
            id uuid PRIMARY KEY,
            channel_id uuid NOT NULL REFERENCES channels(id),
            operation_id uuid NOT NULL,
            device_id uuid NOT NULL REFERENCES devices(id),
            nonce bytea NOT NULL CHECK (octet_length(nonce) = 12),
            ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 16 AND 4112),
            status text NOT NULL CHECK (status IN ('open', 'claimed', 'done', 'cancelled')),
            generation integer NOT NULL DEFAULT 0 CHECK (generation >= 0),
            claimed_by uuid REFERENCES devices(id),
            lease_until timestamptz,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            UNIQUE (device_id, operation_id),
            CHECK ((status = 'claimed') = (claimed_by IS NOT NULL AND lease_until IS NOT NULL))
        )
    """)
    op.execute("CREATE INDEX tasks_queue ON tasks (channel_id, status, created_at)")
    if role := runtime_db_role():
        quoted = op.get_bind().dialect.identifier_preparer.quote_identifier(role)
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON tasks TO {quoted}")


def downgrade() -> None:
    op.drop_table("tasks")
