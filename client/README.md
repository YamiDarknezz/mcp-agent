# Cliente

Componente previsto: un puente por dispositivo, una conexión saliente al servidor, una cola local en SQLite y un MCP por `stdio`. La identidad del dispositivo debe quedar bajo control del puente y del almacén seguro del sistema, no en las herramientas del modelo.

El buzón será independiente de la sesión interactiva. Los adaptadores para OpenCode, Codex y Gemini se habilitarán por separado; recibir mensajes no requiere iniciar un turno del modelo.
