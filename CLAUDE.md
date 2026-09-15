# NEXO-BACKEND

Backend (FastAPI) del proyecto de enriquecimiento de indicadores de
compromiso con IA — Seminario de Seguridad de la Información 2026-2,
Grupo 2, Escuela Colombiana de Ingeniería Julio Garavito.

## Stack

- FastAPI + SQLAlchemy 2.0 — **síncrono**, sin async/await.
- PostgreSQL administrado por Supabase — conexión vía `DATABASE_URL`,
  driver `psycopg` (v3).
- Alembic gestiona el esquema. **Nunca** usar `Base.metadata.create_all()`
  contra Supabase — solo está permitido en tests contra el Postgres local
  de Docker.
- Configuración centralizada en `app/core/config.py` con
  `pydantic-settings` — nunca `os.getenv` disperso.
- Tests corren contra un Postgres local en Docker
  (`docker-compose.test.yml`), **nunca** contra Supabase.

## Arquitectura

Tres capas:
- **Interfaz** — FastAPI, endpoints en `app/api/`.
- **Procesamiento** — módulos de dominio en
  `app/{ingestion,normalization,enrichment,correlation,ai_component,reporting}/`,
  lógica pura sin depender de FastAPI (para poder testearse sin levantar
  servidor).
- **Persistencia** — `app/db/` (modelos, repositorios, sesión).

La correlación con MITRE ATT&CK sigue una cadena de **dos etapas
deliberadamente separadas** — esto es central al diseño del proyecto, no
un detalle de implementación:

1. **Resolución de entidad** (tabla `indicator_entity_link`) — si no hay
   evidencia suficiente, el pipeline se corta aquí.
2. **Recuperación de técnicas** (tabla `entity_technique_link`) — solo se
   ejecuta si la etapa 1 tuvo éxito. Nunca forzar una técnica ATT&CK sin
   sustento.

## Roadmap y estado

Plan completo de 9 etapas en `docs/plan-backend-nexo.md`. Prompt detallado
de cada etapa en `docs/etapas/etapa-0X-*.md`.

Trabajamos **una etapa a la vez**: no implementes nada de una etapa
posterior a la que estemos ejecutando en este momento, aunque parezca
conveniente adelantarlo. Al terminar una etapa, se detiene y se reporta —
no continúa automáticamente con la siguiente.

## Reglas del proyecto

- Cambios mínimos y controlados por etapa — no agregues dependencias,
  patrones o funcionalidades que la etapa actual no pida explícitamente.
- Código limpio: separación de responsabilidades, validación de entradas
  con Pydantic, manejo de errores explícito.
- Ninguna credencial hardcodeada — todo por variables de entorno.
- Evitar sobreingeniería y duplicación innecesaria de código.
- Antes de escribir código, revisa el estado actual del repositorio — no
  asumas qué existe ya implementado.