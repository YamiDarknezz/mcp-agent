"""Add the installation, device identity and one-time enrollment state."""

from alembic import op

from server.settings import runtime_db_role

revision = "0002_activation"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE users (
            id uuid PRIMARY KEY,
            display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 100),
            declared_email text CHECK (char_length(declared_email) BETWEEN 1 AND 254),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp()
        )
    """)
    op.execute("""
        CREATE TABLE devices (
            id uuid PRIMARY KEY,
            user_id uuid NOT NULL REFERENCES users(id),
            public_key bytea UNIQUE NOT NULL CHECK (octet_length(public_key) = 32),
            label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 100),
            created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
            revoked_at timestamptz
        )
    """)
    op.execute("""
        CREATE TABLE installation (
            id smallint PRIMARY KEY CHECK (id = 1),
            operator_user_id uuid REFERENCES users(id),
            activated_at timestamptz,
            CHECK ((operator_user_id IS NULL) = (activated_at IS NULL))
        )
    """)
    op.execute("INSERT INTO installation (id) VALUES (1)")
    op.execute("""
        CREATE TABLE enrollment_codes (
            id uuid PRIMARY KEY,
            digest bytea UNIQUE NOT NULL CHECK (octet_length(digest) = 32),
            purpose text NOT NULL CHECK (purpose IN ('bootstrap', 'pair')),
            issuer_device_id uuid REFERENCES devices(id),
            created_at timestamptz NOT NULL,
            expires_at timestamptz NOT NULL CHECK (expires_at > created_at),
            revoked_at timestamptz,
            consumed_at timestamptz,
            challenge text,
            challenge_expires_at timestamptz,
            candidate_device_id uuid,
            candidate_key bytea CHECK (octet_length(candidate_key) = 32),
            CHECK ((purpose = 'bootstrap') = (issuer_device_id IS NULL)),
            CHECK ((challenge IS NULL) = (challenge_expires_at IS NULL) AND
                   (challenge IS NULL) = (candidate_device_id IS NULL) AND
                   (challenge IS NULL) = (candidate_key IS NULL))
        )
    """)
    op.execute("""
        CREATE UNIQUE INDEX enrollment_one_bootstrap ON enrollment_codes (purpose)
        WHERE purpose = 'bootstrap' AND revoked_at IS NULL AND consumed_at IS NULL
    """)
    op.execute("""
        CREATE UNIQUE INDEX enrollment_one_pair_per_issuer ON enrollment_codes (issuer_device_id)
        WHERE purpose = 'pair' AND revoked_at IS NULL AND consumed_at IS NULL
    """)
    op.execute("""
        CREATE TABLE device_proofs (
            device_id uuid NOT NULL REFERENCES devices(id),
            proof_id uuid NOT NULL,
            expires_at timestamptz NOT NULL,
            PRIMARY KEY (device_id, proof_id)
        )
    """)
    op.execute("CREATE INDEX device_proof_expiry ON device_proofs (device_id, expires_at)")
    op.execute("""
        CREATE TABLE security_events (
            id uuid PRIMARY KEY,
            action text NOT NULL,
            subject_id uuid,
            created_at timestamptz NOT NULL DEFAULT clock_timestamp()
        )
    """)

    if role := runtime_db_role():
        # The role is deployment configuration. Quote its identifier, not a SQL literal.
        quoted = op.get_bind().dialect.identifier_preparer.quote_identifier(role)
        op.execute(f"GRANT SELECT ON installation, users, devices, enrollment_codes, device_proofs, security_events TO {quoted}")
        op.execute(f"GRANT INSERT ON users, devices, enrollment_codes, device_proofs, security_events TO {quoted}")
        op.execute(f"GRANT UPDATE (display_name, declared_email) ON users TO {quoted}")
        op.execute(f"GRANT UPDATE (operator_user_id, activated_at) ON installation TO {quoted}")
        op.execute(f"GRANT UPDATE (revoked_at) ON devices TO {quoted}")
        op.execute(
            "GRANT UPDATE (revoked_at, consumed_at, challenge, challenge_expires_at, "
            f"candidate_device_id, candidate_key) ON enrollment_codes TO {quoted}"
        )
        op.execute(f"GRANT DELETE ON device_proofs TO {quoted}")


def downgrade() -> None:
    for table in ("security_events", "device_proofs", "enrollment_codes", "installation", "devices", "users"):
        op.drop_table(table)
