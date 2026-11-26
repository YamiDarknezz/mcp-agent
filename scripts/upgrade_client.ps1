$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'

if (-not (Test-Path $python)) {
    throw "No se encontró el entorno virtual en $python. Crea uno con: python -m venv .venv"
}

git -C $root pull --ff-only
& $python -m pip install -r (Join-Path $root 'client\requirements.txt')
& $python -c 'from client.relay_mcp import create_server; print("Cliente Relay actualizado; reinicia el proceso MCP.")'
