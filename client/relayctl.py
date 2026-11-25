"""Human-only enrollment and pairing console."""

import argparse
from getpass import GetPassWarning, getpass
import json
import os
import sys
import warnings

if __package__:
    from .relay_identity import DeviceVault, IdentityError, enroll, enrollment_lock, identify, issue_pair_code, server_origin
else:
    from relay_identity import DeviceVault, IdentityError, enroll, enrollment_lock, identify, issue_pair_code, server_origin


def _code(pipe: bool) -> str:
    if pipe:
        return sys.stdin.read(257).strip()
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            return getpass("Código de Relay (oculto): ").strip()
    except (GetPassWarning, EOFError):
        raise IdentityError("Usa una terminal privada para introducir el código.") from None


def _register(args, origin, vault):
    with enrollment_lock(origin):
        key = vault.load()
        if key:
            try:
                identify(origin, key)
            except IdentityError as error:
                if error.status != 401:
                    raise
            else:
                # Recover when a previous claim committed but its HTTP response was lost.
                print("Esta laptop ya está registrada.")
                return 0
        expected = "relay_boot_" if args.command == "activate" else "relay_pair_"
        code = _code(args.code_stdin)
        if not code.startswith(expected):
            raise IdentityError("El código no corresponde a este tipo de alta.")
        key = key or vault.load_or_create()
        enroll(origin, key, code, args.label, getattr(args, "name", None), getattr(args, "email", None))
        print("Laptop registrada. La clave quedó en el almacén seguro del sistema.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Relay device enrollment.")
    parser.add_argument("--server", default=os.getenv("MCP_AGENT_SERVER_URL"))
    sub = parser.add_subparsers(dest="command", required=True)
    activate = sub.add_parser("activate")
    activate.add_argument("--name", required=True)
    activate.add_argument("--email")
    join = sub.add_parser("join")
    for command in (activate, join):
        command.add_argument("--label", required=True)
        command.add_argument("--code-stdin", action="store_true", help="Read from a private pipe, not a command argument.")
    sub.add_parser("whoami")
    sub.add_parser("pair")
    args = parser.parse_args()

    try:
        origin = server_origin(args.server)
    except ValueError:
        parser.error("Indica el origen HTTPS de Relay sin credenciales.")

    try:
        vault = DeviceVault(origin)
        if args.command in {"activate", "join"}:
            return _register(args, origin, vault)
        key = vault.load()
        if not key:
            raise IdentityError("Esta laptop no tiene una identidad de Relay.")
        if args.command == "pair":
            if not sys.stdout.isatty():
                raise IdentityError("Genera el código desde una terminal privada, fuera del agente.")
            print(issue_pair_code(origin, key))
        else:
            print(json.dumps(identify(origin, key)))
        return 0
    except IdentityError as error:
        print(str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
