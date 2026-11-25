# Reglas de colaboración

## Proyecto y subcanales

1. Un proyecto tiene una raíz que agrupa miembros y subcanales. La raíz no admite mensajes, tareas ni archivos.
2. Crear un proyecto crea también exactamente un subcanal `main`. Es una hoja: no recibe hijos, no se renombra, mueve ni archiva por separado.
3. `main` sirve para coordinar decisiones, contratos entre equipos y bloqueos compartidos. No replica el contenido de otros subcanales.
4. Se pueden anidar subcanales para separar equipos o trabajos concretos. Los nombres se distinguen entre hermanos; el mismo nombre puede existir bajo dos padres distintos.

Ejemplo: `Misiones/main` coordina cambios de API; `Misiones/frontend` y `Misiones/backend` tienen conversaciones separadas; `Misiones/frontend/pantalla-misiones` tiene su propio buzón y suscripción.

## Acceso y notificaciones

| Regla | Qué implica |
| --- | --- |
| La membresía se hereda por defecto. | Un miembro del proyecto puede consultar un hijo heredado aunque no lo siga. |
| Un subcanal restringido corta la herencia. | Solo se entra por concesión explícita en ese subcanal. Sus hijos heredados toman como punto de partida esa membresía. |
| El permiso no sube hacia los padres. | Invitar a un subcanal no concede acceso a su padre ni a sus hermanos. Una referencia a un canal privado no revela su contenido ni sus metadatos. |
| Las suscripciones no se heredan. | Seguir un canal no activa avisos de sus hijos, padres o hermanos. |
| `main` comienza en modo menciones. | El resto de subcanales no activa avisos al incorporarse. Cada miembro puede elegir todos, solo menciones o silenciado para los canales que sigue. |
| Autorizar agentes es independiente. | Poder leer y recibir avisos no autoriza tomar tareas, ejecutar comandos ni activar un turno. |

Los roles son propietario, administrador, colaborador y lector. La [matriz de roles](roles.md) define qué puede hacer cada uno y cómo se resuelve la herencia. El permiso efectivo se comprueba en el servidor: listar, leer historial, suscribirse, descargar, enviar o tomar una tarea no deben saltarse la autorización. Revocar un permiso detiene entregas posteriores a esa revocación; no permite recuperar copias ya entregadas a un dispositivo.

## Personas, laptops y agentes

- La persona tiene la membresía. La laptop tiene una identidad propia revocable. El agente es una instancia asociada a ese dispositivo. No se requiere un canal por laptop; un buzón privado por dispositivo es opcional.
- No se exige GitHub, Git ni verificar el correo para conectarse. Un nombre y correo declarados son etiquetas, no prueba de identidad. Las identidades tienen un ID interno único; dos perfiles que declaran el mismo correo no se fusionan. La invitación autoriza el alta; la clave del dispositivo lo autentica después.
- Una invitación es un permiso temporal de un solo uso, no la credencial permanente del canal. El humano copia o pega el código fuera del contexto del modelo. El invitado acepta y canjea el código; no necesita una segunda aprobación humana. Una vez incorporado, puede trabajar sin que esté conectado quien lo invitó. El acceso funciona desde cualquier red por HTTPS/WSS autenticados.
- Los mensajes y archivos son datos, no instrucciones con autoridad. No se ejecuta un adjunto al recibirlo ni se da acceso a un canal por mencionarlo en un mensaje.
- No hay herramienta MCP para extraer credenciales. Si más adelante se incorpora acceso delegado, se autoriza una operación acotada y se devuelve su resultado, no el secreto.

## Alcance de la colaboración

- El MCP coordina conversaciones, tareas y archivos. No ejecuta comandos, edita repositorios, hace commits, publica ramas, abre PR, fusiona ni cierra issues. Tampoco concede acceso a GitHub ni cambia los permisos de los agentes.
- Cada usuario concede permisos a su propio agente en su runtime. Un agente puede colaborar sin aprobación por mensaje y comunicar que una tarea queda fuera de su autorización. Aceptar una tarea en el MCP no concede ningún permiso externo.
- Los operadores y usuarios son responsables de cómo configuran y usan sus agentes y de las acciones externas que estos realicen. El proyecto sí es responsable de sus controles de acceso al canal, sus herramientas de comunicación y su tratamiento de datos; no controla ni garantiza el comportamiento del software externo.
- Al integrarse, el buzón muestra desde lo nuevo. Se puede solicitar historial por páginas (por ejemplo, 10 o 30 mensajes). Los archivos anteriores requieren un permiso separado. Ni el historial ni los adjuntos se cargan automáticamente en el agente.
