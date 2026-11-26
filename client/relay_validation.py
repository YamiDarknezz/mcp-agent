"""Actionable validation results for MCP tools.

The tools return these dictionaries instead of raising, so an agent sees what
to correct (and which tool can provide a valid value) in the tool response.
"""

from typing import Any


def _error(tool: str, problems: list[str]) -> dict[str, Any] | None:
    return {"error": f"{tool}: " + "; ".join(problems)} if problems else None


def page_error(tool: str, after: int, limit: int, max_limit: int = 10) -> dict[str, Any] | None:
    problems = []
    if not isinstance(after, int) or after < 0:
        problems.append(f"after debe ser >= 0 (recibido {after!r}); usa after=0 para empezar")
    if not isinstance(limit, int) or not 1 <= limit <= max_limit:
        problems.append(f"limit debe estar entre 1 y {max_limit} (recibido {limit!r}); usa limit={max_limit}")
    return _error(tool, problems)


def limit_error(tool: str, limit: int, max_limit: int = 100) -> dict[str, Any] | None:
    if not isinstance(limit, int) or not 1 <= limit <= max_limit:
        return _error(tool, [f"limit debe estar entre 1 y {max_limit} (recibido {limit!r}); usa limit={max_limit}"])
    return None


def choice_error(tool: str, field: str, value: str, choices: set[str]) -> dict[str, Any] | None:
    if value not in choices:
        options = ", ".join(sorted(choices))
        return _error(tool, [f"{field} debe ser uno de {options} (recibido {value!r})"])
    return None


def channel_error(tool: str, channel_id: str) -> dict[str, Any] | None:
    if not isinstance(channel_id, str) or not channel_id.strip():
        return _error(tool, ["channel_id es obligatorio; obtenlo con list_channels o list_subscriptions"])
    return None
