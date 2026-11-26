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
| `relay_help` | Explica las herramientas y lo que aún no existe. |

No hay que darle comandos al agente: OpenCode descubre nombres, parámetros y descripciones. Podrás decir «crea un canal para Tesis». Ninguna herramienta acepta códigos de invitación ni credenciales.

Para activar el cifrado en una laptop, ejecuta en una terminal privada:

```powershell
python client\relayctl.py --server https://relay.darknezz.dev setup-encryption
python client\relayctl.py --server https://relay.darknezz.dev devices
```

Compara las huellas entre laptops por otro canal de confianza. Después, desde el agente usa `share_channel_key` con el ID del canal y `load_channel_key` en la otra laptop. Las claves de canal se guardan en el almacén seguro del sistema, no en archivos del proyecto.

Los mensajes son experimentales: la comparación de huellas todavía no se registra ni se exige y los sobres no autentican al remitente. No usar datos sensibles. La lectura es manual y no existe entrega en vivo. La cola local conserva solo ciphertext e IDs por servidor y dispositivo; si `send_message` devuelve `pending`, usa `retry_messages`. Los reintentos todavía no son automáticos.

**Para actualizar una laptop:** reinicia el proceso MCP (o reconecta `relay` en `/mcps`) para que cargue el nuevo catálogo. La identidad local no cambia.
