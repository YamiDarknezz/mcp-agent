"""Local-only operator commands, invoked from the server's console."""

import argparse
import asyncio
import sys
from uuid import UUID

from sqlalchemy.exc import SQLAlchemyError

from server import identity, settings


async def _operator_action(args):
    engine = identity.new_engine()
    try:
        async with engine.begin() as conn:
            if args.command == "issue-bootstrap":
                issued = await identity.issue_bootstrap(conn, settings.enrollment_code_ttl())
            else:
                await identity.revoke_device(conn, args.device_id)
        if args.command == "issue-bootstrap":
            print(issued["code"], flush=True)
        else:
            print("Device revoked.")
    finally:
        await engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    issue = sub.add_parser("issue-bootstrap")
    issue.add_argument("--pipe", action="store_true", help="Explicitly emit into a trusted private pipe.")
    revoke = sub.add_parser("revoke-device")
    revoke.add_argument("device_id", type=UUID)
    revoke.add_argument("--confirm", action="store_true", required=True)
    args = parser.parse_args()
    if args.command == "issue-bootstrap" and not (sys.stdout.isatty() or args.pipe):
        parser.error("Run from a private console or set --pipe and pipe into a trusted client.")
    try:
        asyncio.run(_operator_action(args))
    except identity.Denied as error:
        if error.status == 409:
            print("This installation is already activated; no code was issued.", file=sys.stderr)
        else:
            print("Operator action rejected.", file=sys.stderr)
        return 1
    except (settings.ConfigurationError, OSError, SQLAlchemyError):
        print("Operator action failed; check the database and deployment configuration.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
