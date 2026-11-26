# Primera activación de Relay

Una instalación nueva arranca **sin operador y sin registro abierto**. El alta se hace en una terminal privada. Ninguna herramienta MCP acepta o devuelve códigos.

## Registrar la primera laptop

1. Desde el checkout del servidor, ejecuta en privado `docker compose --env-file /ruta/al/despliegue/.env -f compose.yaml -f compose.prod.yaml exec api python -m server.manage issue-bootstrap`.
2. En la laptop instala [`client/requirements.txt`](../client/requirements.txt) en tu entorno virtual. Con el Python de ese entorno ejecuta:

   ```console
   python client/relayctl.py --server https://agentes.example.com activate --name "Ana" --label "Laptop de Ana"
   ```

   Pega el código cuando se te pida; la entrada no se muestra. `--server` también puede venir de `MCP_AGENT_SERVER_URL`, sin credenciales.

El código dura 15 minutos por defecto (`MCP_ENROLLMENT_TTL_SECONDS`, entre 60 y 3600), solo sirve una vez y el servidor guarda únicamente un hash. Reemitir antes del alta invalida el anterior. PostgreSQL consume el código y registra persona y dispositivo en la misma transacción. La clave privada se guarda en la laptop antes de solicitar el canje, para poder recuperar la identidad si se pierde la respuesta.

## Añadir otra laptop tuya

1. En la primera, ejecuta `python client/relayctl.py --server https://agentes.example.com pair-start` en una terminal privada. El nombre anterior `pair` sigue funcionando como alias.
2. En la segunda, instala las mismas dependencias y ejecuta `python client/relayctl.py --server https://agentes.example.com pair-join --label "Segunda laptop"`. El nombre anterior `join` sigue funcionando como alias. Pega el código en el prompt oculto.
3. En ambas puedes verificar la identidad con `whoami` o con `relay.status` si configuraste el MCP local.

**El emparejamiento añade un dispositivo a la misma cuenta, incluido el rol de operador si lo tiene. No es una invitación para un compañero.** Las dos laptops tienen claves independientes. Desde el servidor puedes revocar una con `python -m server.manage revoke-device ID --confirm` dentro del contenedor de la API; no revoques tu último dispositivo sin un plan de recuperación.

Después del alta no se reabre la activación por reiniciar o perder una laptop. El rol de operador no da acceso a contenido de canales ajenos ni ejecuta acciones en Git. Proyectos, invitaciones para compañeros, sincronización y cifrado de canales son cortes posteriores.
