from alembic import context
from sqlalchemy import create_engine
from sqlalchemy.pool import NullPool

from server.settings import POSTGRES_MAJOR, ConfigurationError, database_url

if context.is_offline_mode():
    raise ConfigurationError("Migrations must run against an explicit PostgreSQL instance.")

engine = create_engine(
    database_url(),
    connect_args={"connect_timeout": 5},
    poolclass=NullPool,
    hide_parameters=True,
)
try:
    with engine.begin() as connection:
        version = connection.exec_driver_sql("SHOW server_version_num").scalar_one()
        if int(version) // 10000 != POSTGRES_MAJOR:
            raise ConfigurationError(f"Migrations require PostgreSQL {POSTGRES_MAJOR}.")
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()
finally:
    engine.dispose()
