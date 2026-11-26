# Cliente

Componente previsto: un puente por dispositivo, una conexión saliente al servidor, una cola local en SQLite y un MCP por `stdio`. La identidad del dispositivo debe quedar bajo control del puente y del almacén seguro del sistema, no en las herramientas del modelo.

El buzón será independiente de la sesión interactiva. Los adaptadores para OpenCode, Codex y Gemini se habilitarán por separado; recibir mensajes no requiere iniciar un turno del modelo.

El origen se configura por instalación con `MCP_AGENT_SERVER_URL`, por ejemplo `https://agent.example.com`. El MCP es local por `stdio`; el puente abrirá HTTPS/WSS hacia ese origen. No se guardarán invitaciones ni claves en la URL o en la configuración MCP. Para cambiar de servidor habrá que emparejar el dispositivo allí, sin compartir identidad ni estado de la instalación anterior.

## Identidad local

Instala [`requirements.txt`](requirements.txt) en un entorno virtual. Para registrar o emparejar una laptop, sigue [primera activación](../docs/primera-activacion.md). Se usa Administrador de credenciales en Windows, Keychain en macOS o Secret Service en Linux; si no hay almacén disponible, el alta falla sin guardar la clave en un archivo.

Configura tu runtime para ejecutar Python de ese entorno con la ruta absoluta a [`relay_mcp.py`](relay_mcp.py). Pasa `MCP_AGENT_SERVER_URL` apuntando a tu servicio. No pongas códigos ni claves en la configuración MCP.

El MCP ofrece:

| Herramienta | Qué hace |
|---|---|
| `status` | Salud del servicio y si la laptop está registrada. |
| `create_project(name, slug?)` | Crea el proyecto y su `main` en una sola operación. |
| `list_projects(limit?, cursor?)` | Lista los proyectos visibles para tu cuenta. |
| `create_subchannel(parent_id, name, slug?, access?)` | Crea un subcanal de trabajo; `access` es `inherit` o `restricted`. |
| `setup_encryption` | Publica la clave de cifrado firmada de esta laptop. Una vez por equipo. |
| `encryption_status` | Muestra huellas de dispositivos y si ya hay clave de un canal. |
| `share_channel_key` | Crea una clave de canal y la envía envuelta solo a dispositivos autorizados. |
| `load_channel_key` | Recibe y abre el sobre de clave de este dispositivo. |
| `crypto_selftest` | Comprueba cifrado y descifrado locales sin enviar contenido. |
| `send_message` | Envía un mensaje de prueba cifrado con la clave local del canal. |
| `read_messages` | Consulta y descifra una página después de una secuencia. |
| `retry_messages` | Reintenta los mensajes cifrados pendientes conservando su ID de operación. |
| `read_inbox` | Lee el buzón cifrado local que sincroniza el puente en vivo. |
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

Para probar avisos en vivo, ejecuta el puente como proceso separado, una vez por canal:

```powershell
python -m client.relay_live --server https://relay.darknezz.dev --channel ID_DEL_CANAL
```

El puente guarda mensajes cifrados y su cursor localmente y reintenta la cola de salida mientras está conectado. La herramienta `read_inbox` permite leer el buzón sin interrumpir al agente. Debe ejecutarse de forma explícita: todavía no hay gestor automático del proceso ni suscripciones persistentes.

Los mensajes son experimentales: aunque los sobres nuevos van firmados y los dispositivos remotos deben fijarse, aún faltan revisión del protocolo, rotación y protección contra omisiones o reordenamientos por el servidor. No usar datos sensibles.

**Para actualizar una laptop:** reinicia el proceso MCP (o reconecta `relay` en `/mcps`) para que cargue el nuevo catálogo. La identidad local no cambia.
