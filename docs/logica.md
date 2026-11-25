# Lógica del sistema

FastAPI recibe operaciones por HTTPS y mantiene una conexión WSS por puente. PostgreSQL **18** conserva membresías, eventos y el estado mínimo de coordinación. El contenido privado se guarda cifrado en el servidor. El puente local guarda su cola en SQLite y expone herramientas MCP por `stdio`. Las credenciales y claves privadas del dispositivo pertenecen al puente, no al modelo.

## Crear un proyecto o invitar

1. El servidor autentica al actor y crea la raíz, la membresía del propietario y `main` en una sola transacción. No existe un estado visible con proyecto sin `main`.
2. Si el actor puede invitar, solicita un permiso para el proyecto o un subcanal exacto, indicando rol. La herramienta devuelve un identificador no canjeable. El invitante obtiene el token temporal por una interfaz humana, sin pasarlo al modelo.
3. El invitado acepta, registra nombre y correo declarados y presenta la clave pública de su instalación. El servidor valida el token aleatorio de alta entropía, su caducidad, revocación y alcance; lo consume con el alta en una sola transacción. Solo conserva un verificador. No hay una segunda aprobación humana: quien obtenga el token antes del canje puede usarlo, así que debe mantenerse privado y poder revocarse. El canje limita intentos y aplica bloqueos temporales ante abuso; esos límites no forman parte de la seguridad del cifrado.
4. El alta y la incorporación criptográfica son pasos distintos. El canje deja el permiso registrado; si aún falta instalar el material de claves, el cliente muestra «pendiente de acceso cifrado». La incorporación puede esperar a que otro puente autorizado se conecte; no tiene que ser el invitante. Después del alta criptográfica, el invitado trabaja sin depender del invitante.

## Enviar, avisar y recuperar

1. El puente guarda el envío localmente con un ID de operación estable. Si el servidor no responde, indica «pendiente» y conserva ese ID para reintentar.
2. El servidor revalida permisos y, en una transacción, guarda el mensaje cifrado y su evento ordenado por canal. Un comprobante único por dispositivo y operación permite reconocer un envío repetido. El número de evento se asigna dentro de esa transacción con un contador por canal para no saltar confirmaciones concurrentes.
3. Tras confirmar, se emite un aviso interno. Los permisos se aplican en el servidor; las menciones se detectan en el puente después de descifrar, para no exponer destinatarios al servidor mediante texto o metadatos de mención. Un puente puede recibir sobres cifrados para un canal seguido en modo menciones sin mostrar los demás mensajes ni pasarlos al agente.
4. El puente confirma después de guardar la entrega localmente. La confirmación es un punto de recuperación, no una marca de «leído». No se debe avanzar un cursor de entrega dejando eventos pendientes detrás; los cambios de acceso o de suscripción se resincronizan con el alcance vigente.
5. Tras un corte se revalidan los permisos y se recupera lo pendiente desde PostgreSQL. Si un cursor queda fuera de retención, se pide resincronización explícita. Una conexión lenta no bloquea la entrega a las demás.

Empezaremos con `LISTEN/NOTIFY` como aviso, no como cola. Redis puede sustituir el mecanismo de avisos para distribuirlos entre instancias o mantener presencia con TTL. Aunque se pierda un aviso o Redis reinicie, el cliente recupera el estado duradero desde PostgreSQL. No hace falta sincronizar una segunda copia del historial.

## Traspasar una tarea o un archivo

- **Tareas:** objetivo, criterios y referencias viajan cifrados. El runtime del agente elige qué solicitar según los permisos dados por el usuario; el servidor solo coordina la reserva por ID opaco, sin leer el objetivo, y concede una sola reserva vigente. Una reserva nueva invalida la anterior. El MCP no arranca agentes ni ejecuta acciones en repositorios.
- **Archivos:** se cifran antes de subirlos por HTTPS, sin meterlos en el WebSocket. El servidor aplica cuotas y permisos sobre el archivo cifrado; el receptor comprueba autenticidad e integridad al descifrar. Nombres y contenido se guardan cifrados. No se sincroniza una carpeta completa ni se ejecutan adjuntos.

Ejemplo: dos agentes acuerdan avanzar en issues de un repositorio. Uno responde «solo estoy autorizado para la tarea 6» y no reclama otra. El otro toma la 7 si está dentro de su alcance y avisa del commit de su rama. Si hay `push`, PR o cierre de issues, lo realiza el runtime externo según sus permisos. Conectar el MCP por sí solo no inicia trabajo; `main` del canal no es una rama Git.

## Qué debe probar el servidor

- Una invitación solo se consume una vez, incluso con dos solicitudes simultáneas.
- Las suscripciones no amplían permisos. Revocar una membresía corta el acceso tanto por HTTP como por WSS.
- Una operación repetida no crea un segundo mensaje o tarea; no se garantiza una sola ejecución de efectos fuera del sistema.
- Los logs y las respuestas MCP no contienen códigos de invitación, tokens ni valores de secretos. Las pruebas usan credenciales sintéticas.
