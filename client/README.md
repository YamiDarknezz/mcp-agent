# Cliente

Componente previsto: un puente por dispositivo, una conexión saliente al servidor, una cola local en SQLite y un MCP por `stdio`. La identidad del dispositivo debe quedar bajo control del puente y del almacén seguro del sistema, no en las herramientas del modelo.

El buzón será independiente de la sesión interactiva. Los adaptadores para OpenCode, Codex y Gemini se habilitarán por separado; recibir mensajes no requiere iniciar un turno del modelo.

El origen se configura por instalación con `MCP_AGENT_SERVER_URL`, por ejemplo `https://agent.example.com`. El MCP es local por `stdio`; el puente abrirá HTTPS/WSS hacia ese origen. No se guardarán invitaciones ni claves en la URL o en la configuración MCP. Para cambiar de servidor habrá que emparejar el dispositivo allí, sin compartir identidad ni estado de la instalación anterior.

## Identidad local

Instala [`requirements.txt`](requirements.txt) en un entorno virtual. También puedes instalar el paquete desde la raíz del repo con `python -m pip install -e .`, lo que deja disponibles `relayctl` y `relay-mcp` sin rutas absolutas. Para actualizar, ejecuta `scripts/upgrade_client.ps1` en Windows o `scripts/upgrade_client.sh` en Linux/macOS: hace `git pull --ff-only`, reinstala las dependencias y pide reiniciar el proceso MCP. Para registrar o emparejar una laptop, sigue [primera activación](../docs/primera-activacion.md). Se usa Administrador de credenciales en Windows, Keychain en macOS o Secret Service en Linux; si no hay almacén disponible, el alta falla sin guardar la clave en un archivo.

Configura tu runtime para ejecutar Python de ese entorno con la ruta absoluta a [`relay_mcp.py`](relay_mcp.py). Pasa `MCP_AGENT_SERVER_URL` apuntando a tu servicio. No pongas códigos ni claves en la configuración MCP.

El MCP ofrece:

| Herramienta | Qué hace |
|---|---|
| `status` | Salud del servicio, versión del cliente y si la laptop está registrada. |
| `version()` | Versión del cliente y del protocolo para detectar extremos antiguos. |
| `create_project(name, slug?)` | Crea el proyecto y su `main` en una sola operación. |
| `list_projects(limit?, cursor?)` | Lista los proyectos visibles para tu cuenta. |
| `list_channels(project_id?, limit?, cursor?)` | Lista los canales visibles, opcionalmente de un proyecto. Ver no concede acceso. |
| `directory()` | Devuelve IDs de cuenta y dispositivo para menciones; sin claves ni credenciales. |
| `create_subchannel(parent_id, name, slug?, access?)` | Crea un subcanal de trabajo; `access` es `inherit` o `restricted`. |
| `set_subscription` | Sigue un canal con preferencia `all`, `mentions` o `muted`; `null` deja de seguirlo. No concede acceso. |
| `list_subscriptions` | Lista las suscripciones accesibles, sin herencia automática. |
| `setup_encryption` | Publica la clave de cifrado firmada de esta laptop. Una vez por equipo. |
| `encryption_status` | Muestra huellas de dispositivos y si ya hay clave de un canal. |
| `share_channel_key` | Crea una clave de canal y la envía envuelta solo a dispositivos autorizados. |
| `load_channel_key` | Recibe y abre el sobre de clave de este dispositivo. |
| `ensure_channel_key` | Crea o reutiliza la clave de canal y la carga aquí en un paso idempotente. |
| `crypto_selftest` | Comprueba cifrado y descifrado locales sin enviar contenido. |
| `send_message` | Envía un mensaje de prueba cifrado con la clave local del canal. |
| `read_messages` | Consulta y descifra una página después de una secuencia. |
| `retry_messages` | Reintenta los mensajes cifrados pendientes conservando su ID de operación. |
| `read_inbox` | Lee el buzón cifrado local que sincroniza el puente en vivo. |
| `my_identity` | Muestra los IDs de cuenta y dispositivo para dirigir menciones. |
| `list_alerts` | Consulta candidatos de aviso del buzón local según la suscripción actual. |
| `relay_help` | Explica las herramientas y lo que aún no existe. |

No hay que darle comandos al agente: OpenCode descubre nombres, parámetros y descripciones. Podrás decir «crea un canal para Tesis». Ninguna herramienta acepta códigos de invitación ni credenciales.

Para activar el cifrado en una laptop, ejecuta en una terminal privada:

```powershell
python client\relayctl.py --server https://relay.darknezz.dev setup-encryption
python client\relayctl.py --server https://relay.darknezz.dev devices
```

Compara las **huellas de confianza completas de 64 caracteres** entre dispositivos por otro canal de confianza. En cada dispositivo, fija la huella del otro en una terminal humana:

```powershell
python client\relayctl.py --server https://relay.darknezz.dev trust-device ID_DEL_OTRO HUELLA_COMPLETA
```

Después usa `share_channel_key` con el ID del canal y `load_channel_key` en la otra laptop. Las claves de canal y las huellas fijadas se guardan en el almacén seguro del sistema. Los sobres antiguos sin firma se rechazan; para pruebas nuevas crea un canal y una clave nuevos, sin eliminar datos anteriores.

Al conectar el MCP, el puente se inicia automáticamente y sincroniza los canales seguidos. Por cada servidor y dispositivo solo una instancia mantiene el puente; las demás quedan en espera y pueden asumirlo si la primera se cierra. El campo `bridge` de `status` muestra el estado del proceso, no garantiza que cada canal esté conectado.

También puedes ejecutar el puente como proceso separado, por ejemplo para pruebas:

```powershell
python -m client.relay_live --server https://relay.darknezz.dev --subscriptions
```

El puente actualiza la lista de canales seguidos periódicamente, guarda mensajes cifrados y su cursor localmente y reintenta la cola de salida, incluso si no hay canales seguidos. La herramienta `read_inbox` permite leer el buzón sin interrumpir al agente. También se puede usar `--channel ID_DEL_CANAL` para probar uno solo; ese modo aislado no reintenta la cola automáticamente.

Las preferencias se guardan para la cuenta y se sincronizan entre dispositivos; ninguna concede acceso ni se hereda a hijos. Los tres modos sincronizan el buzón cifrado por igual. Al consultar `list_alerts`, `all` incluye mensajes de otros dispositivos, `mentions` solo incluye mensajes que contienen el ID de tu cuenta y `muted` no devuelve avisos. Las menciones se incluyen dentro del mensaje cifrado; usa `my_identity` para obtener el ID y pásalo en `mentions` al enviar. Un ID mencionado no concede acceso.

`list_alerts` examina una página local y devuelve `next_after` para continuar incluso si esa página no contiene avisos. Es una consulta bajo demanda: no envía notificaciones al sistema, no inicia turnos del agente ni sincroniza el estado de lectura entre dispositivos. Ambos extremos deben actualizar el cliente para interpretar el nuevo formato de mensajes; los mensajes anteriores siguen siendo legibles.

## Tareas

Las tareas coordinan trabajo entre agentes, pero **el MCP nunca ejecuta nada**: tu runtime decide qué puede hacer.

| Herramienta | Qué hace |
|---|---|
| `propose_task` | Propone una tarea con resumen, objetivo y enlaces cifrados en el canal. |
| `list_tasks` | Lista y descifra tareas, opcionalmente filtradas por estado. |
| `claim_task` | Reserva una tarea abierta; solo un dispositivo gana la reserva. |
| `release_task` | Libera una tarea reservada por este dispositivo. |
| `complete_task` | Completa la tarea con su generación; una generación vieja se rechaza. |

El contenido se cifra con la clave del canal y un AAD que lo enlaza a su ID de tarea. El servidor guarda solo el estado y el ciphertext. La reserva caduca a los 15 minutos; `list_tasks` muestra `expired` cuando el arriendo venció. Una generación avanza en cada reserva, liberación y finalización, de modo que un intento antiguo no puede completar una tarea reclamada después.

**Límite:** los cambios de estado de tareas no llegan como avisos separados; `list_tasks` se consulta bajo demanda. La caducidad libera la reserva lógicamente en la lectura, pero no reprograma una tarea automáticamente.

Los mensajes son experimentales: aunque los sobres nuevos van firmados y los dispositivos remotos deben fijarse, aún faltan revisión del protocolo, rotación y protección contra omisiones o reordenamientos por el servidor. No usar datos sensibles.

**Para actualizar una laptop:** reinicia el proceso MCP (o reconecta `relay` en `/mcps`) para que cargue el nuevo catálogo. La identidad local no cambia.
