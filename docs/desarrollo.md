# Desarrollo local

El entorno local levanta una API y PostgreSQL 18 en Docker. Redis es un complemento opcional; este corte acepta su configuración, pero todavía no lo usa para distribuir eventos.

## Arrancar y probar

Requisitos: Git, Docker Engine o Docker Desktop y Docker Compose con `up --wait`. Los siguientes comandos son para PowerShell y se ejecutan desde la raíz del repositorio. No se necesita `.env` para el entorno local predeterminado.

```powershell
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $true
$stack = @('compose','-p','mcp-agent-dev','-f','compose.yaml','-f','compose.dev.yaml')
docker @stack config --quiet
docker @stack up -d --wait --wait-timeout 60 db
docker @stack build api
docker @stack run --rm --no-deps -T api python -m unittest discover -s server/tests -v
docker @stack run --rm --no-deps -T migrate
docker @stack run --rm --no-deps -T migrate python -m server.migrate --check
docker @stack up -d --no-build --wait --wait-timeout 90 api
Invoke-RestMethod http://127.0.0.1:8765/health
Invoke-RestMethod http://127.0.0.1:8765/ready
```

Si un paso falla, corrígelo antes de continuar. `/health` debe mostrar `ok`; `/ready` debe mostrar `ready` solo si la API accede a una base PostgreSQL **18** con la migración aplicada. El volumen de PostgreSQL 18 se monta en `/var/lib/postgresql`, no en la ruta de versiones anteriores.

Solo se publica la API en loopback (`127.0.0.1:8765`); puedes cambiar el puerto con `MCP_DEV_PORT`. PostgreSQL no publica puertos y su contraseña del ejemplo es **exclusivamente local**. Usa las credenciales y redes del [despliegue propio](despliegue.md) para contextos compartidos.

Para incluir Redis, añade `'-f','compose.redis.dev.yaml'` al final de `$stack` **antes** de ejecutar el bloque y arranca los dos servicios:

```powershell
docker @stack up -d --wait --wait-timeout 60 db redis
docker @stack exec -T redis redis-cli ping
```

`PONG` confirma que el Redis local responde. No se publica un puerto de Redis. Usa las mismas capas para `docker @stack ps`, `docker @stack logs --tail 50 api` o `docker @stack down`. `down` sin `--volumes` conserva los datos.

CI repite este flujo contra PostgreSQL 18 y Redis en un runner Linux. Al agregar una migración, incluye una prueba en PostgreSQL real para sus restricciones y ejecútala antes de probar la API. Por ahora Alembic solo crea el marcador inicial: no existen tablas de colaboración ni un WebSocket de aplicación.
