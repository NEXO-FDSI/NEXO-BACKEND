# Plan de implementación — Backend NEXO

Proyecto: Seminario de Seguridad de la Información 2026-2 — Grupo 2
Repos: NEXO-BACKEND (FastAPI) · NEXO-FRONTEND (React/Vite) — sin monorepo

## Arquitectura

| Aspecto | Decisión |
|---|---|
| Framework | FastAPI |
| ORM | SQLAlchemy 2.0 (síncrono) |
| Driver Postgres | psycopg[binary] (psycopg 3) |
| Migraciones | Alembic |
| Configuración | pydantic-settings |
| Base de datos | PostgreSQL administrado por Supabase (`DATABASE_URL` en `.env`) |
| Módulos de dominio | `ingestion / normalization / enrichment / correlation / ai_component / reporting` — lógica pura, sin acoplar a FastAPI |
| Testing | pytest + Postgres en Docker local para tests |
| Seguridad | Validación con Pydantic, exception handlers centralizados, `.env` fuera de git, service_role key de Supabase nunca expuesta al frontend |
| Despliegue | Docker, conexión cloud-ready por diseño |

## Modelo de datos (8 tablas — diseño acordado, pendiente de implementar en el repo)

`indicators`, `enrichment_cache`, `entities`, `indicator_entity_link`, `techniques`, `entity_technique_link`, `reports`, `human_validation`.

El repo aún no tiene `app/db/database.py` ni `app/db/models.py` — solo el scaffolding inicial (estructura de carpetas, `/health`, CORS). Este modelo se implementa por primera vez en la Etapa 1, directamente sobre PostgreSQL.

La separación `indicator_entity_link` / `entity_technique_link` refleja la cadena de dos etapas del proyecto: (a) resolución de entidad, (b) recuperación de técnicas — (b) solo se ejecuta si (a) tuvo éxito.

## Roadmap de etapas

### Etapa 1 — Base de datos y modelo de datos sobre PostgreSQL/Supabase
- Objetivo: crear desde cero la conexión a Postgres/Supabase y el modelo de datos de las 8 tablas, con Alembic gestionando el esquema (no hay migración desde SQLite — nunca se implementó en el repo).
- Implementa: `app/core/config.py`, `app/db/database.py`, `app/db/models.py`, Alembic inicializado, migración inicial con las 8 tablas.
- Dependencias: ninguna (parte del scaffolding actual).
- Verificación: `alembic current`, tablas visibles en Supabase, `/health` responde OK.
- Aceptación: backend conectado a Postgres real, modelo de datos completo, cero referencias a SQLite.
- Estado: **✅ completada**.

### Etapa 2 — Capa de acceso a datos y schemas Pydantic
- Objetivo: repositorios CRUD básicos + schemas request/response por entidad.
- Implementa: `app/db/repositories/`, `app/schemas/`.
- Dependencias: Etapa 1.
- Verificación: tests unitarios de CRUD contra Postgres local en Docker.
- Aceptación: cada tabla tiene su repositorio y schema, sin lógica de negocio todavía.
- Estado: **prompt listo** (ver `etapa-02-repositorios-schemas.md`).

### Etapa 3 — Ingesta de indicadores
- Objetivo: endpoint que recibe y valida indicadores (IP/dominio/hash/URL).
- Implementa: `app/ingestion/`, `POST /indicators`.
- Dependencias: Etapa 2.
- Verificación: tests con indicadores válidos e inválidos por tipo.
- Aceptación: indicadores persistidos correctamente, rechazo claro de formatos inválidos.

### Etapa 4 — Normalización
- Objetivo: dedup y estandarización integrados al flujo de ingesta.
- Implementa: `app/normalization/`.
- Dependencias: Etapa 3.
- Verificación: test de indicador en variantes (mayúsculas, defanged) → colapsa a un solo registro.
- Aceptación: no se crean duplicados lógicos.

### Etapa 5 — Enriquecimiento
- Objetivo: integración con API de reputación (ThreatFox/OTX), con caché.
- Implementa: `app/enrichment/`, uso real de `enrichment_cache`.
- Dependencias: Etapa 4.
- Verificación: test con indicador conocido (hit) y uno sin evidencia (miss).
- Aceptación: respuesta explícita de "sin evidencia" cuando corresponde; caché evita llamadas repetidas.

### Etapa 6 — Integración MITRE ATT&CK + correlación
- Objetivo: cargar el STIX (enterprise-attack-19.1.json), indexarlo, implementar resolución de entidad y recuperación de técnicas.
- Implementa: `app/correlation/`.
- Dependencias: Etapa 5.
- Verificación: test que confirma que si la etapa (a) falla, la etapa (b) no se ejecuta.
- Aceptación: cadena de dos etapas implementada tal como está en el documento del proyecto.

### Etapa 7 — Reporting + validación humana
- Objetivo: generación de informe estructurado (aún sin IA) y endpoints de aceptar/rechazar.
- Implementa: `app/reporting/`, `POST /reports/{id}/validate`.
- Dependencias: Etapa 6.
- Verificación: test de integración indicador → informe → validación.
- Aceptación: `reports` y `human_validation` se llenan correctamente.

### Etapa 8 — Componente de IA (LLM + RAG)
- Objetivo: integrar el LLM (Ollama local en dev, swap a API real por configuración) sobre el índice ATT&CK ya cargado.
- Implementa: `app/ai_component/`, vector store sobre el dataset ATT&CK.
- Dependencias: Etapa 6.
- Verificación: los 6 escenarios de prueba corriendo contra el dataset curado.
- Aceptación: control de alucinación funcionando — declara "sin asociación" cuando corresponde.

### Etapa 9 — Testing completo, documentación y hardening
- Objetivo: cobertura end-to-end, OpenAPI revisado, seguridad final.
- Dependencias: todas las anteriores.
- Verificación: suite completa en verde, revisión manual de `/docs`.
- Aceptación: backend listo para conectar con el frontend.

## Metodología de ejecución

Una etapa a la vez. El prompt de Claude Code de cada etapa se genera inmediatamente después de validar la etapa anterior, para que refleje fielmente las decisiones y nombres que Claude Code haya usado realmente — no una suposición hecha de antemano.