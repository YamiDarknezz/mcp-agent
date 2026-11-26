"""Centralized, actionable validation for MCP tool arguments."""

from uuid import UUID


def _error(parameter: str, problem: str, fix: str) -> dict:
    return {"error": f"{parameter}: {problem}. {fix}"}


def limit(value, *, minimum: int = 1, maximum: int = 100) -> dict | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return _error("limit", "debe ser un número entero", f"Pasa un entero entre {minimum} y {maximum}.")
    if not minimum <= value <= maximum:
        return _error("limit", f"valor {value} fuera de rango", f"Usa un entero entre {minimum} y {maximum}.")
    return None


def after(value: int) -> dict | None:
    if isinstance(value, bool) or not isinstance(value, int):
        return _error("after", "debe ser un número entero", "Usa 0 para empezar desde el primer mensaje.")
    if value < 0:
        return _error("after", f"valor {value} es negativo", "Usa 0 para empezar o un seq devuelto por read_messages.")
    return None


def channel_id(value) -> dict | None:
    if not isinstance(value, str):
        return _error("channel_id", "falta o no es texto", "Copia el ID devuelto por list_channels o create_subchannel.")
    try:
        parsed = UUID(value)
    except ValueError:
        return _error("channel_id", "no es un UUID válido", "Copia el ID completo desde list_channels.")
    if parsed.version != 4 or str(parsed) != value.lower():
        return _error("channel_id", "no es un UUID v4 en minúsculas", "Usa el ID exacto que devuelve Relay.")
    return None


def choice(value, allowed: set[str], name: str = "valor") -> dict | None:
    if value not in allowed:
        options = ", ".join(sorted(allowed))
        return _error(name, f"valor {value!r} no reconocido", f"Usa uno de: {options}.")
    return None
