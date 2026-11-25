# Plan de implementación

## Orden de trabajo

| Hito | Entregable | Criterio de aceptación |
| --- | --- | --- |
| 0A. Infraestructura | API base, Compose local y de producción, PostgreSQL 18, Alembic y CI/CD optativo. | Un entorno vacío construye la imagen, migra y supera `/health` y `/ready`. El Compose de producción no crea PostgreSQL ni Redis. |
| 0B. Prueba criptográfica | Probar alta, cifrado de grupo, historial y revocación en Windows. | El servidor guarda solo contenido cifrado. Una laptop nueva genera su propia clave y recupera historial paginado mediante otro miembro autorizado. Una laptop revocada no descifra contenido nuevo. La biblioteca funciona en Windows y CI. |
| 1. Proyecto y acceso | Alta sin GitHub obligatorio, identidad de dispositivo, raíz con `main`, subcanales, membresías e invitación de un solo uso. | Dos personas canjean y operan sin configurar Git; hay un solo `main`; la raíz no admite interacciones; un invitado directo no accede a ancestros ni hermanos. |
| 2. Comunicación en vivo | Puente local, herramientas MCP mínimas, WSS, reintentos, suscripciones y recuperación. | Dos laptops, primero con OpenCode y Codex, intercambian mensajes. Cortar la red durante el envío y reconectar no duplica la operación ni interrumpe un turno. Seguir `frontend` no genera avisos de `backend`. Objetivo a medir: p95 inferior a un segundo entre dispositivos conectados, sin contar la respuesta del modelo. |
| 3. Tareas y artefactos | Reservas, traspasos cifrados y permisos en descargas. | Dos agentes coordinan issues distintos desde sus runtimes sin que el MCP toque Git. Dos agentes no obtienen la misma reserva. Revocar corta las nuevas descargas. |
| 4. Operación y compatibilidad | Despliegue aislado por Docker Compose detrás de Traefik, respaldo probado y adaptador para el cliente Gemini que se elija. | Tras reiniciar servidor o puente se recupera el estado. Se restaura una copia de base y archivos. Pasan las pruebas de no exposición de secretos. |

Redis se incorpora si las mediciones muestran que aporta valor para la distribución de avisos, presencia o cuotas entre instancias. No se necesita para implementar ni probar el historial duradero.

Para ejecutar 0A, ver [desarrollo local](desarrollo.md). Para instalar en otro dominio o configurar servicios compartidos, ver [despliegue propio](despliegue.md). El CI/CD solo comprueba HTTP y PostgreSQL en este corte; antes de habilitar un servicio real, hay que añadir pruebas de WSS autenticado, reconexión y privacidad.

## Decisiones confirmadas

- GitHub puede ser una comodidad, no una condición. Se puede ingresar con nombre y correo declarados, aceptando una invitación larga de un solo uso sin segunda aprobación humana. Tras incorporarse, no se depende del invitante.
- Acceso desde cualquier red mediante HTTPS/WSS en el dominio del despliegue. Laptops y PostgreSQL no necesitan puertos públicos.
- Cifrado de extremo a extremo para contenido. Los mensajes nuevos aparecen primero, el historial se consulta por páginas y los archivos históricos tienen permiso separado. Una nueva laptop recibe otra invitación, genera claves propias y recupera historial con autorización de un administrador o propietario del subcanal, siempre que quede el material necesario en un dispositivo autorizado.
- Si el canje se realiza con los puentes autorizados desconectados, el alta criptográfica puede esperar a que alguno se conecte. Tras completarla no se depende del invitante.
- Cuatro [roles por alcance](roles.md): propietario, administrador, colaborador y lector. La política local tiene pruebas unitarias; la validación por HTTP/WSS, persistencia y protocolos de claves son parte de los hitos 0 y 1.
- El MCP ofrece comunicación y coordinación, no ejecución. El usuario y su runtime externo gestionan los permisos del agente, incluidas las acciones sobre el repositorio.

## Decisiones que faltan

| Decisión | Propuesta para el primer corte | Qué condiciona |
| --- | --- | --- |
| Implementación de cifrado y claves históricas | Probar opciones con una biblioteca mantenida y dispositivos Windows. No exponer llaves al VPS ni reutilizar secretos de épocas previas para compartir historial. | Disponibilidad, rotación, recuperación y protección contra sustitución de claves. |
| Límites de invitación | Usar vigencia corta, controles de intentos y revocación; fijar valores tras probar el alta en redes compartidas. | Reducir abuso sin bloquear equipos legítimos detrás de la misma IP. |
