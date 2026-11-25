# Despliegue propio

Necesitas Docker Compose, **PostgreSQL 18** y un dominio que apunte a tu proxy HTTPS. Redis es opcional. La composición de producción solo levanta la API y ejecuta migraciones; PostgreSQL y Redis pueden ser compartidos y no deben exponerse a Internet.

1. Clona el repositorio en el servidor. Copia [`.env.example`](../.env.example) como `.env` en un directorio **fuera** del checkout. Configura `MCP_DOMAIN`, el nombre del proyecto y las redes externas. Traefik debe estar en `MCP_PROXY_NETWORK`, con el entrypoint TLS y el resolver configurados; PostgreSQL debe ser accesible desde `MCP_DATA_NETWORK`.
2. Crea una base propia y dos roles: uno para migrar y otro para la API. En `MCP_RUNTIME_SECRETS_DIR/database-url` guarda la DSN de la API y en `MCP_MIGRATION_DATABASE_URL_PATH` la del migrador. El runtime necesita acceso al esquema y `SELECT` sobre `alembic_version`. Mantén los archivos privados y legibles por el GID `10001` del contenedor. Redis se configura, si hace falta, con `MCP_REDIS_URL_FILE`.
3. Desde el checkout de `main`, despliega el SHA que probaste:

   ```bash
   bash scripts/deploy.sh "$SHA_PROBADO" /ruta/al/repositorio /ruta/al/despliegue
   ```

   Verifica `/health` y `/ready` por HTTPS. La API no publica puertos de host: Traefik reenvía al puerto interno `8000` y admite WSS en el mismo dominio.

## CI/CD opcional

El [workflow](../.github/workflows/ci-cd.yml) prueba PostgreSQL 18, migra y despliega solo desde `main`. En el environment `production`, limita la rama a `main` y configura los secrets `VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY` y `VPS_KNOWN_HOSTS` (entrada `known_hosts` verificada). El puerto 22 se puede cambiar con `VPS_SSH_PORT`.

Instala [`ssh-receiver.sh`](../scripts/ssh-receiver.sh) fuera del checkout y usa una llave dedicada en `authorized_keys` con `restrict,command="/ruta/ssh-receiver.sh /ruta/al/repositorio /ruta/al/despliegue"`. La llave debe aceptar solo `deploy SHA`, no abrir una shell. Activa el job con la variable de repositorio `VPS_DEPLOY_ENABLED=true`.

Cuando exista el puente, cada laptop apuntará al origen elegido con `MCP_AGENT_SERVER_URL=https://agent.example.com`. No pongas credenciales en la URL.
