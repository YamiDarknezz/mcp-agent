#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python="$root/.venv/bin/python"

if [[ ! -x "$python" ]]; then
  echo "No se encontró el entorno virtual en $python. Crea uno con: python -m venv .venv" >&2
  exit 1
fi

git -C "$root" pull --ff-only
"$python" -m pip install -r "$root/client/requirements.txt"
"$python" -c 'from client.relay_mcp import create_server; print("Cliente Relay actualizado; reinicia el proceso MCP.")'
