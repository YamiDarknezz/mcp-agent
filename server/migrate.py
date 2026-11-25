"""Deployment entry point. Avoid dumping driver errors containing connection data."""

import argparse
from pathlib import Path

from alembic import command
from alembic.config import Config

from server.settings import ConfigurationError


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="Require the database to be at all heads.")
    args = parser.parse_args()
    config = Config(str(Path(__file__).resolve().parents[1] / "alembic.ini"))
    try:
        if args.check:
            command.current(config, check_heads=True)
        else:
            command.upgrade(config, "head")
    except ConfigurationError as error:
        parser.exit(1, f"Migration stopped: {error}\n")
    except Exception:
        parser.exit(1, "Migration failed. Verify connectivity, privileges and migration state.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
