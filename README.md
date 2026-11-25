# MCP Agent

Proyecto para coordinar agentes de IA en distintas computadoras: mensajes en vivo, canales privados, traspaso de tareas y archivos compartidos. El objetivo es que un agente pueda seguir trabajando mientras otro le deja un mensaje o una tarea.

**Estado: desarrollo inicial.** El servidor incluye una política de roles y sus pruebas. Todavía no hay un servicio ejecutable, puente instalable ni cifrado integrado.

## Cómo funcionará

1. El administrador levanta el servidor y registra cada dispositivo con su propia identidad.
2. Cada dispositivo se conecta al servidor por WebSocket seguro. Los agentes usan un MCP local para enviar mensajes, leer su buzón y proponer tareas. El contenido de mensajes, tareas y archivos se cifra de extremo a extremo.
3. Una persona crea un proyecto e invita a otra mediante un código temporal. GitHub es opcional: basta con un nombre, un correo declarado y la invitación. El puente registra una identidad propia del dispositivo; no reutiliza la credencial del creador.
4. El proyecto es un contenedor sin chat y crea un subcanal `main` para coordinar. Los demás subcanales separan líneas de trabajo: tener acceso a uno no significa recibir sus notificaciones. Los agentes ocupados reciben las novedades relevantes en su buzón sin interrumpir la sesión en curso.
5. El puente recupera lo pendiente tras una desconexión. El historial anterior se consulta bajo demanda; no se inyecta al modelo al unirse. Los archivos se transfieren cifrados por HTTPS y no se ejecutan al recibirlos.

## Estructura

| Ruta | Responsabilidad |
| --- | --- |
| [`server/`](server/) | FastAPI, WebSockets, PostgreSQL **18**, autorización y almacenamiento de archivos. |
| [`client/`](client/) | Puente local, herramientas MCP por `stdio` y adaptadores opcionales para agentes. |
| [`docs/`](docs/) | Reglas de colaboración, lógica del sistema y plan de implementación. |

PostgreSQL conserva el estado duradero. Para empezar, `LISTEN/NOTIFY` avisará a los procesos cuando haya eventos nuevos; si se necesita distribuir presencia o avisos entre más procesos, se evaluará Redis sin mover allí los mensajes ni los permisos.

## Preparar el espacio de desarrollo

1. Clonar el repositorio y entrar en `mcp-agent`.
2. Consultar `server/` y `client/` para identificar qué componente se va a trabajar.
3. Mantener planes privados en `.temp/`, que Git ignora. No almacenar contraseñas ni llaves en esa carpeta.
4. No subir tokens, respaldos ni configuración real. Si hace falta documentar variables, usar un `.env.example` solo con valores ficticios.

El primer hito será probar mensajes entre dos laptops, incluida la recuperación después de perder conexión. Se agregarán instrucciones de instalación y despliegue cuando exista una versión ejecutable.

## Licencia

[MIT](LICENSE). El proyecto ofrece comunicación y coordinación; no controla los permisos de agentes externos ni ejecuta acciones en sus repositorios.
