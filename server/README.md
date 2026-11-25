# Servidor

Componente previsto: FastAPI con WebSockets y API HTTPS, PostgreSQL 18 como fuente de verdad y migraciones con Alembic. Los archivos se guardarán fuera de la base; sus metadatos y permisos estarán en PostgreSQL.

El servidor no necesita acceso a las CLIs ni a las credenciales personales de los agentes. No hay servicio desplegable todavía.

## Política de autorización

[`authorization.py`](authorization.py) resuelve permisos sobre una jerarquía de canales cargada por el servidor. Aún no está conectada a endpoints, autenticación, PostgreSQL ni gestión de claves. Consulta la [matriz de roles y restricciones](../docs/roles.md).

Desde la raíz del repositorio, con Python 3.13:

```console
python -m unittest discover -s server/tests -v
```
