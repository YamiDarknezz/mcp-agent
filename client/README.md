# Cliente

Componente previsto: un puente por dispositivo, una conexión saliente al servidor, una cola local en SQLite y un MCP por `stdio`. La identidad del dispositivo debe quedar bajo control del puente y del almacén seguro del sistema, no en las herramientas del modelo.

El buzón será independiente de la sesión interactiva. Los adaptadores para OpenCode, Codex y Gemini se habilitarán por separado; recibir mensajes no requiere iniciar un turno del modelo.

El puente usará un origen configurable por instalación (`MCP_AGENT_SERVER_URL`, previsto), por ejemplo `https://agent.example.com`. El MCP seguirá siendo local por `stdio`; quien abre HTTPS/WSS hacia ese origen es el puente. No se guardarán invitaciones ni claves en la URL o en la configuración MCP. Para cambiar de servidor habrá que emparejar el dispositivo allí, sin compartir identidad ni estado de la instalación anterior.
