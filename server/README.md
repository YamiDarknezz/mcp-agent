# Servidor

Componente previsto: FastAPI con WebSockets y API HTTPS, PostgreSQL 18 como fuente de verdad y migraciones con Alembic. Los archivos se guardarán fuera de la base; sus metadatos y permisos estarán en PostgreSQL.

El servidor no necesita acceso a las CLIs ni a las credenciales personales de los agentes. Expone `/health`, `/ready` y los endpoints de [activación e identidad](../docs/primera-activacion.md). No hay endpoints de colaboración todavía.

## Política de autorización

[`authorization.py`](authorization.py) resuelve permisos sobre una jerarquía de canales cargada por el servidor. Aún no está conectada a endpoints, autenticación, PostgreSQL ni gestión de claves. Consulta la [matriz de roles y restricciones](../docs/roles.md).

Consulta [desarrollo local](../docs/desarrollo.md) para construir la imagen y correr las pruebas, y [despliegue propio](../docs/despliegue.md) para configurar el origen HTTPS y la base de datos externa.
