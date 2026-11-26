"""Human-only enrollment and pairing console."""

import argparse
from getpass import GetPassWarning, getpass
import json
import os
import sys
import warnings

if __package__:
    from .relay_identity import DeviceVault, IdentityError, enroll, enrollment_lock, identify, issue_pair_code, server_origin
    from .relay_keys import list_devices, public_device_fingerprint, setup as setup_encryption, trust_device
    from .relay_invites import issue as issue_invite, redeem as redeem_invite
else:
    from relay_identity import DeviceVault, IdentityError, enroll, enrollment_lock, identify, issue_pair_code, server_origin
    from relay_keys import list_devices, public_device_fingerprint, setup as setup_encryption, trust_device
    from relay_invites import issue as issue_invite, redeem as redeem_invite


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


COMMAND_ALIASES = {"pair": "pair-start", "join": "pair-join"}


def normalize_command(command: str) -> str:
    """Map legacy command names to their canonical, self-describing forms."""
    return COMMAND_ALIASES.get(command, command)


def main() -> int:
    parser = argparse.ArgumentParser(description="Relay device enrollment.")
    parser.add_argument("--server", default=os.getenv("MCP_AGENT_SERVER_URL"))
    sub = parser.add_subparsers(dest="command", required=True)
    activate = sub.add_parser("activate")
    activate.add_argument("--name", required=True)
    activate.add_argument("--email")
    join = sub.add_parser(
        "pair-join", aliases=["join"], help="Consume un código de emparejamiento en esta laptop."
    )
    for command in (activate, join):
        command.add_argument("--label", required=True)
        command.add_argument("--code-stdin", action="store_true", help="Read from a private pipe, not a command argument.")
    sub.add_parser("whoami")
    sub.add_parser(
        "pair-start", aliases=["pair"], help="Genera un código para emparejar otra laptop tuya."
    )
    sub.add_parser("setup-encryption", help="Publica la clave de cifrado firmada de esta laptop.")
    sub.add_parser("devices", help="Muestra huellas de los dispositivos para comparar fuera de banda.")
    trust = sub.add_parser("trust-device", help="Fija una huella comprobada fuera de Relay.")
    trust.add_argument("device_id")
    trust.add_argument("fingerprint", help="Huella completa de identidad de 64 caracteres.")
    invite = sub.add_parser("invite-issue", help="Emite una invitación de un solo uso para un subcanal.")
    invite.add_argument("--channel", required=True)
    invite.add_argument("--role", default="reader", choices=["reader", "collaborator", "admin"])
    invite.add_argument("--expires-in", type=int)
    redeem = sub.add_parser("invite-redeem", help="Canjea una invitación desde un prompt oculto.")
    redeem.add_argument("--code-stdin", action="store_true", help="Lee el código desde un pipe privado.")
    redeem.add_argument("--display-name", required=True, help="Nombre de la persona invitada.")
    redeem.add_argument("--device-label", required=True, help="Etiqueta de esta laptop.")
    redeem.add_argument("--email", help="Correo declarado; no concede privilegios.")
    args = parser.parse_args()
    args.command = normalize_command(args.command)

    try:
        origin = server_origin(args.server)
    except ValueError:
        parser.error("Indica el origen HTTPS de Relay sin credenciales.")

    try:
        vault = DeviceVault(origin)
        if args.command in {"activate", "join"}:
            return _register(args, origin, vault)
        if args.command == "setup-encryption":
            result = setup_encryption(origin)
            print('Dispositivo ' + result['device_id'])
            print('Huella: ' + result['fingerprint'])
            print('Huella de confianza: ' + result['trust_fingerprint'])
            print('Compara esta huella con la otra laptop por un canal de confianza.')
            return 0
        if args.command == "devices":
            devices = list_devices(origin)["devices"]
            for device in devices:
                fingerprint = public_device_fingerprint(device, origin) if device.get("encryption_key") else "sin cifrado"
                print('{0} | {1} | {2}'.format(device["label"], device["id"], fingerprint))
            return 0
        if args.command == "trust-device":
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise IdentityError("Confirma la huella desde una terminal humana de confianza.")
            trust_device(origin, args.device_id, args.fingerprint)
            print("Huella fijada para este dispositivo.")
            return 0
        if args.command in {"invite-issue", "invite-redeem"}:
            if not sys.stdin.isatty() or not sys.stdout.isatty():
                raise IdentityError("Las invitaciones se emiten y canjean en una terminal privada, fuera del agente.")
            if args.command == "invite-issue":
                result = issue_invite(origin, args.channel, args.role, args.expires_in)
                print("Código de invitación (un solo uso, no lo compartas por el agente):")
                print(result["code"])
                print("Vence: " + str(result.get("expires_at", "desconocida")))
            else:
                code = _code(args.code_stdin)
                result = redeem_invite(origin, code, args.display_name, args.device_label, args.email)
                print("Membresía aceptada: " + str(result["channel_id"]) + " como " + str(result["role"]))
            return 0
        key = vault.load()
        if not key:
            raise IdentityError("Esta laptop no tiene una identidad de Relay.")
        if args.command == "pair-start":
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
