# Roles y restricciones

Los roles son membresías de personas en un alcance concreto. No son roles de GitHub ni de la laptop. Un dispositivo o un agente no gana permisos por declararse administrador en una solicitud. Operar el VPS permite administrar el servicio, no leer los canales ni compartir sus claves.

## Matriz

| Acción | Lector | Colaborador | Administrador | Propietario |
| --- | --- | --- | --- | --- |
| Ver y seguir un subcanal autorizado, leer mensajes, consultar historial y tareas, descargar archivos actuales | Sí | Sí | Sí | Sí |
| Descargar archivos anteriores | Con permiso separado | Con permiso separado | Con permiso separado | Con permiso separado |
| Publicar mensajes, proponer o tomar tareas, subir archivos | — | Sí | Sí | Sí |
| Crear subcanales fuera de `main` | — | — | Sí | Sí |
| Invitar, cambiar o revocar lectores y colaboradores | — | — | Sí | Sí |
| Invitar, cambiar o revocar administradores | — | — | — | Sí |
| Habilitar historial de mensajes o una concesión separada de archivos históricos | — | — | Sí | Sí |
| Archivar el alcance, excepto `main` por separado | — | — | — | Sí |

Las invitaciones y los cambios ordinarios no crean ni eliminan propietarios. La creación de un proyecto asignará su propietario inicial. Al crear un subcanal restringido, su creador podrá ser el propietario de ese alcance, sin dar acceso automático al propietario del proyecto. No hay transferencia de propiedad implementada; antes de ofrecerla, debe existir un flujo explícito que no deje el alcance sin propietario.

## Alcance e herencia

1. La raíz admite navegación y administración, no mensajes, tareas, suscripciones ni archivos. `main` es un subcanal obligatorio de coordinación, hereda acceso y no admite hijos.
2. En un subcanal heredado, la concesión más cercana gana. Si alguien es administrador en el proyecto y tiene una concesión directa de lector en `frontend`, solo es lector allí y en los descendientes que hereden de él.
3. Un subcanal restringido corta la herencia para todos, incluido el propietario del proyecto y los administradores de los padres. No hay acceso a hermanos ni a ancestros por tener acceso directo a un hijo.
4. Revocar en un alcance registra un bloqueo de herencia en lugar de borrar la concesión y reactivar una anterior. Si hay concesiones directas independientes en otros subcanales, esas concesiones deben revocarse por separado cuando se busca retirar todo el acceso. Revocar un dispositivo, en cambio, lo invalida en todos sus canales sin alterar las demás laptops de la persona.
5. Seguir un canal o poseer un cursor no concede acceso. Al canjear una invitación se comprueba que su emisor todavía puede conceder el rol. Añadir un dispositivo a una persona existente no cambia sus membresías; una invitación no pisa un rol previo.

## Alta y recuperación cifradas

- El invitado acepta y canjea la invitación de un solo uso sin una segunda aprobación humana. Si falta el alta criptográfica y no hay otro puente autorizado conectado, permanece pendiente; no necesita que se conecte el invitante original. Tras incorporarse, el invitado sigue trabajando aunque este se desconecte.
- Un administrador o propietario **del subcanal** puede habilitar historial a una nueva instalación. La laptop nueva se identifica con una invitación nueva y genera sus propias claves. No basta coincidir en nombre o correo.
- Autorizar historial no permite obtener llaves del VPS: hace falta material disponible en otro dispositivo autorizado o una entrega preparada para el destinatario. Si se perdió ese material, el contenido no se recupera. Un permiso para leer o compartir mensajes históricos no convierte automáticamente los archivos anteriores en descargables.
- La autorización se vuelve a comprobar al despachar por WSS, recuperar historial, descargar, renovar una reserva o hacer un cambio de membresía. Aplicar cambios de membresía y auditoría con estado vigente en una transacción y coordinar las transiciones de claves; conservar copias antiguas en un dispositivo no equivale a tener permiso de acceso futuro.

## Estado actual

El [módulo de autorización](../server/authorization.py) comprueba roles, herencia, límites de invitación y cambios de membresía sobre datos confiables del servidor. Las pruebas unitarias verifican que no se obtenga acceso lateral o ascendente, que un administrador no pueda promoverse ni modificar pares y que los archivos históricos necesiten un permiso independiente. La persistencia, los cambios de claves, la revocación activa y los flujos de alta y recuperación siguen pendientes.
