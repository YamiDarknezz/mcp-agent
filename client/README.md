# Cliente

Componente previsto: un puente por dispositivo, una conexión saliente al servidor, una cola local en SQLite y un MCP por `stdio`. La identidad del dispositivo debe quedar bajo control del puente y del almacén seguro del sistema, no en las herramientas del modelo.

El buzón será independiente de la sesión interactiva. Los adaptadores para OpenCode, Codex y Gemini se habilitarán por separado; recibir mensajes no requiere iniciar un turno del modelo.

El origen se configura por instalación con `MCP_AGENT_SERVER_URL`, por ejemplo `https://agent.example.com`. El MCP es local por `stdio`; el puente abrirá HTTPS/WSS hacia ese origen. No se guardarán invitaciones ni claves en la URL o en la configuración MCP. Para cambiar de servidor habrá que emparejar el dispositivo allí, sin compartir identidad ni estado de la instalación anterior.

## Identidad local

Instala [`requirements.txt`](requirements.txt) en un entorno virtual. Para registrar o emparejar una laptop, sigue [primera activación](../docs/primera-activacion.md). Se usa Administrador de credenciales en Windows, Keychain en macOS o Secret Service en Linux; si no hay almacén disponible, el alta falla sin guardar la clave en un archivo.

Configura tu runtime para ejecutar Python de ese entorno con la ruta absoluta a [`relay_mcp.py`](relay_mcp.py). Pasa `MCP_AGENT_SERVER_URL` apuntando a tu servicio. La herramienta `status` comprueba la salud y si la laptop está registrada; no devuelve credenciales. No pongas códigos ni claves en la configuración MCP.
