# Privacidad y cifrado de extremo a extremo

## Qué protege

- Solo los dispositivos autorizados de un subcanal descifran sus mensajes, datos privados de tareas y archivos. El cliente cifra antes de enviar y descifra localmente. TLS se mantiene para proteger la conexión y la autenticación.
- PostgreSQL y los respaldos del servidor no guardan claves privadas de los dispositivos ni texto de conversaciones. El administrador del VPS no recibe una llave maestra. El servidor aún ve metadatos necesarios: dispositivos conectados, permisos, tiempos, tamaños aproximados y estado operativo de las reservas. No se promete anonimato.
- Un destinatario puede copiar lo que ya leyó. Si un puente entrega contenido descifrado a OpenCode, Codex o Gemini, el contenido puede salir hacia el proveedor del modelo según su configuración. El cifrado del canal no protege contra el proveedor, un dispositivo comprometido ni una actualización maliciosa del cliente.
- Aunque sea posible escribir una contraseña en un mensaje, no usar ese flujo como almacén de secretos. Para un acceso puntual, se prefieren permisos efímeros o una entrega de humano a humano que no cargue el valor al contexto del modelo.

## Claves y acceso

1. Cada instalación genera sus claves localmente y protege el material privado con el almacén del sistema. Registrar un nombre o correo no permite recuperar la clave de otra persona.
2. Por cada subcanal hay un grupo criptográfico separado. La herencia define quién puede incorporarse, no una llave compartida por todos los subcanales. Si cambia la membresía efectiva, el cambio de claves alcanza también a los hijos que heredan.
3. El token de un solo uso basta para aceptar la invitación sin otra aprobación humana. El diseño criptográfico debe proteger además contra la sustitución de claves por el servidor. Evaluar cómo autenticar la incorporación con el material de invitación y una prueba de posesión de la clave del dispositivo, sin confiar solo en el directorio del servidor ni reutilizar el token de canje como clave de mensajes. No prometer garantías contra un servidor activo hasta probar ese flujo.
4. Una revocación corta el acceso en el servidor y cambia el material criptográfico para contenido futuro. Un cliente no debe fallar en modo abierto si la membresía y las claves aún no convergen. Las copias y claves previas que llegó a recibir el exmiembro no pueden retirarse.
5. El token de invitación autoriza el registro, no se usa como clave de contenido ni se intercambia con el agente. Si se ha filtrado antes de su uso, hay que revocarlo y emitir otro. Limitar abusos de canje y autenticación en línea no detecta intentos de descifrado fuera del servidor.

## Historial y rendimiento

El usuario nuevo ve lo que llega desde su alta; el puente ofrece consultar páginas anteriores de 10 o 30 sin cargar todo en el modelo. Los archivos históricos requieren un permiso independiente. **El permiso de historial no es lo mismo que una clave para descifrarlo.** Si alguien cambia o pierde su laptop, vuelve por invitación y genera claves nuevas. Si la vieja se perdió, se revoca; compartir correo o nombre no transfiere identidad ni permisos. Un administrador o propietario del subcanal, desde un dispositivo autorizado, puede habilitar o preparar la entrega cifrada del historial para la nueva instalación, sin exportar su clave privada ni entregar secretos de épocas antiguas del protocolo de grupo. Evaluar claves de contenido separadas o un archivo de historial cifrado. Si todos están desconectados y no hay entrega ya preparada, la incorporación o recuperación espera a que se conecte otro dispositivo autorizado. Si nadie conserva el material necesario, el servidor no puede reconstruirlo.

## Implementación actual

La capa de [`relay_crypto.py`](../client/relay_crypto.py) usa `cryptography` 50: X25519 derivado por HKDF desde la semilla Ed25519 ya guardada, AES-256-GCM con nonce aleatorio de 12 bytes y AAD que enlaza canal y secuencia. Cada subcanal tiene una clave AES de 32 bytes que el servidor nunca recibe.

- Cada dispositivo publica su clave pública X25519 **firmada con su clave Ed25519**. El servidor verifica la firma antes de guardarla, pero no puede demostrar por sí solo que esa Ed25519 pertenece a la persona correcta: por tanto, las huellas se comparan fuera de banda.
- Para compartir una clave de canal, el emisor genera un efímero X25519, deriva una clave de empaquetado con HKDF y cifra la clave del canal con AES-GCM. El servidor guarda solo el sobre opaco. Un servidor que leyera toda su base no puede abrirlo.
- El transporte experimental cifra mensajes con la clave del canal y un AAD con el ID del canal y una parte del ID de operación. La secuencia asignada por el servidor no está autenticada: no se garantiza la detección de reordenamiento u omisión.
- Las claves de canal se guardan por origen y canal en el almacén seguro del sistema, separadas de las claves de autenticación.

**Límites vigentes:** hay envío y lectura manual de mensajes de prueba, y una cola local cifrada con reintento manual, pero no entrega en vivo ni reintentos automáticos. Los sobres no autentican criptográficamente al remitente, y la comparación de huellas no está fijada ni exigida por el cliente; un servidor activo puede sustituir claves. No hay rotación de claves de canal ni recuperación segura de historial. No usar datos sensibles ni anunciar seguridad frente al servidor hasta corregir y probar estos puntos. El cifrado no protege contra un dispositivo comprometido ni contra lo que el modelo haga con un mensaje ya descifrado.
