"""Allow the runtime to modify a user's subscription preferences."""

from alembic import op
from server.settings import runtime_db_role

revision = "0006_subscription_permissions"
down_revision = "0005_messages"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if role := runtime_db_role():
        quoted = op.get_bind().dialect.identifier_preparer.quote_identifier(role)
        op.execute(f"GRANT UPDATE (mode), DELETE ON channel_subscriptions TO {quoted}")


def downgrade() -> None:
    if role := runtime_db_role():
        quoted = op.get_bind().dialect.identifier_preparer.quote_identifier(role)
        op.execute(f"REVOKE UPDATE (mode), DELETE ON channel_subscriptions FROM {quoted}")
