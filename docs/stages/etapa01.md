# Etapa 1 — Creacion modelo de datos y bd en PostgreSQL (Supabase)

## Contexto
Este es el backend (FastAPI) de un proyecto de enriquecimiento de
inteligencia de amenazas con IA. El repositorio actualmente tiene **solo el scaffolding inicial**:
estructura de carpetas (`app/{ingestion,normalization,enrichment,correlation,
ai_component,reporting,api,db}`), entorno virtual, `requirements.txt` básico
(fastapi, uvicorn, pydantic, sqlalchemy, httpx, python-dotenv, pandas,
pytest), un `app/main.py` con un endpoint `GET /health` y CORS configurado, y
un `Dockerfile`. **Todavía no existe ninguna capa de base de datos** — no hay
`app/db/database.py`, no hay `app/db/models.py`, no hay conexión a ninguna
base de datos configurada.

Vamos a construir la capa de persistencia **directamente sobre PostgreSQL
administrado por Supabase**. Esta es la primera etapa de un plan de desarrollo dividido en
9 etapas verificables; en esta etapa NO se implementa ninguna lógica de
negocio, solo la base de datos y el modelo de datos.

## Objetivo

Dejar el backend conectado a una instancia real de PostgreSQL en Supabase,
con el modelo de datos de las 8 tablas creado desde cero y su esquema
gestionado por Alembic (nunca por `create_all()`), y la configuración
centralizada con pydantic-settings.

## Alcance

- Crear la conexión a PostgreSQL vía `DATABASE_URL` (Supabase).
- Introducir `pydantic-settings` para centralizar configuración.
- Crear el modelo de datos SQLAlchemy con las 8 tablas (`indicators`,
  `enrichment_cache`, `entities`, `indicator_entity_link`, `techniques`,
  `entity_technique_link`, `reports`, `human_validation`).
- Introducir Alembic para migraciones versionadas.
- Generar y aplicar la migración inicial que crea las 8 tablas en Supabase.
- Verificar conexión exitosa contra la instancia real de Supabase.

## Fuera de alcance

- No implementar endpoints de negocio (ingesta, normalización, enriquecimiento, etc.).
- No implementar lógica de correlación con MITRE ATT&CK ni componente de IA.
- No implementar autenticación ni autorización.
- No modificar el frontend.
- No usar SQLAlchemy async — mantener el estilo síncrono ya existente.

## Esquema de datos (referencia obligatoria — no improvisar columnas)

**indicators**
| Columna | Tipo | Constraints |
|---|---|---|
| id | Integer | PK, autoincrement |
| tipo | String | not null — valores esperados: `ip` / `domain` / `hash` / `url` |
| valor | String | not null, unique, index |
| fuente | String | nullable |
| timestamp_ingesta | DateTime | default now (UTC) |

**enrichment_cache**
| Columna | Tipo | Constraints |
|---|---|---|
| id | Integer | PK |
| indicator_id | Integer | FK → indicators.id, not null |
| fuente_api | String | not null |
| respuesta_json | Text | not null |
| timestamp | DateTime | default now (UTC) |

**entities**
| Columna | Tipo | Constraints |
|---|---|---|
| id | Integer | PK |
| nombre | String | not null |
| tipo | String | not null — valores esperados: `malware` / `grupo` / `campaña` / `herramienta` |

**indicator_entity_link** (etapa a — resolución de entidad)
| Columna | Tipo | Constraints |
|---|---|---|
| id | Integer | PK |
| indicator_id | Integer | FK → indicators.id, not null |
| entity_id | Integer | FK → entities.id, not null |
| evidencia | Text | nullable |
| confianza | Float | not null — rango 0.0–1.0 |

**techniques**
| Columna | Tipo | Constraints |
|---|---|---|
| id | String | PK — id oficial ATT&CK, ej. `"T1566"` (no autoincrement) |
| nombre | String | not null |
| tactica | String | not null |

**entity_technique_link** (etapa b — recuperación de técnicas)
| Columna | Tipo | Constraints |
|---|---|---|
| id | Integer | PK |
| entity_id | Integer | FK → entities.id, not null |
| technique_id | String | FK → techniques.id, not null |
| fuente_attck | String | nullable |

**reports**
| Columna | Tipo | Constraints |
|---|---|---|
| id | Integer | PK |
| indicator_id | Integer | FK → indicators.id, not null |
| contenido | Text | not null |
| nivel_confianza | Float | not null |
| timestamp | DateTime | default now (UTC) |

**human_validation**
| Columna | Tipo | Constraints |
|---|---|---|
| id | Integer | PK |
| report_id | Integer | FK → reports.id, not null |
| decision | String | not null — valores esperados: `aceptado` / `rechazado` |
| analista | String | nullable |
| timestamp | DateTime | default now (UTC) |

Todos los `DateTime` con `default now (UTC)` deben usar una función timezone-aware (`datetime.now(timezone.utc)`), no `datetime.utcnow()` (deprecado).

## Tareas

1. Revisar el estado actual del repositorio antes de escribir código:
   estructura de `app/`, contenido de `app/main.py`, `requirements.txt`,
   `.env.example` — confirmar que efectivamente no existe ya ninguna capa
   de base de datos.
2. Agregar dependencias y actualizar `requirements.txt`: confirmar/ajustar
   `sqlalchemy>=2.0`, agregar `psycopg[binary]`, `alembic`,
   `pydantic-settings`.
3. Crear `app/core/config.py` con una clase `Settings(BaseSettings)` que
   centralice: `DATABASE_URL`, `LLM_API_KEY`, `REPUTATION_API_KEY`,
   `CORS_ORIGINS`. Debe leer desde `.env`. Si `app/main.py` ya lee
   `CORS_ORIGINS` con `os.getenv`, migrarlo a usar `Settings`.
4. Crear `app/db/database.py`: `create_engine(settings.DATABASE_URL)`,
   `SessionLocal`, `Base = declarative_base()`, y una función `get_db()`
   como dependencia de FastAPI (generator que abre/cierra sesión).
5. Crear `app/db/models.py` con las 8 tablas y sus relaciones, siguiendo
   **exactamente** la sección "Esquema de datos" de este documento — no
   improvisar ni agregar columnas adicionales. Respetar el diseño de la
   cadena de dos etapas: `indicator_entity_link` modela la etapa (a) de
   resolución de entidad; `entity_technique_link` modela la etapa (b) de
   recuperación de técnicas (la lógica de que (b) solo se pueble si (a)
   tuvo éxito se implementa en una etapa posterior — aquí solo se define
   el esquema).
6. Actualizar `.env.example`: agregar `DATABASE_URL` con el formato
   `postgresql+psycopg://user:password@host:port/dbname` como placeholder
   (sin credenciales reales). Actualizar `.env` local con las credenciales
   reales de Supabase (este archivo no se commitea).
7. Inicializar Alembic (`alembic init alembic`) y configurar
   `alembic/env.py` para que use `settings.DATABASE_URL` y
   `target_metadata = Base.metadata` desde `app/db/models.py`.
8. Generar la migración inicial autogenerada
   (`alembic revision --autogenerate -m "initial schema"`) capturando las
   8 tablas recién definidas.
9. Aplicar la migración contra la instancia real de Supabase
   (`alembic upgrade head`).
10. Confirmar que el endpoint `/health` sigue funcionando sin cambios
    funcionales (no debe depender de la base de datos).

## Reglas de implementación

- No usar async/await — mantener SQLAlchemy síncrono.
- Usar exactamente los 8 nombres de tabla y las relaciones especificadas en
  la tarea 5, para mantener consistencia con el resto del plan de etapas.
- No hardcodear ningún valor de conexión — todo por variables de entorno,
  leído a través de `Settings`.
- No commitear el archivo `.env` real ni ninguna credencial.
- Seguir la convención de nombres y carpetas ya existente en el repo.
- No introducir dependencias adicionales fuera de las listadas en la tarea 2.

## Verificación

- `alembic current` debe mostrar la revisión aplicada.
- Confirmar en el Table Editor de Supabase (o vía `psql`) que las 8 tablas
  existen con las columnas, tipos y foreign keys esperadas.
- Levantar el servidor: `uvicorn app.main:app --reload --port 8000` sin
  errores de conexión en el arranque.
- `curl http://localhost:8000/health` debe responder `{"status": "ok"}`.
- Ejecutar `alembic downgrade base` y luego `alembic upgrade head` para
  confirmar que la migración es reversible sin errores. Al terminar esta
  prueba, el esquema debe quedar aplicado (en `head`), no revertido.

## Criterios de aceptación

- El backend se conecta exitosamente a PostgreSQL en Supabase usando
  únicamente `DATABASE_URL` desde `.env`.
- Las 8 tablas existen en Supabase con las columnas, tipos y foreign keys
  exactos definidos en la sección "Esquema de datos" de este documento —
  sin columnas de más ni de menos.
- Alembic gestiona el esquema — ya no depende de `create_all()`.
- El endpoint `/health` sigue respondiendo correctamente.


## Resultado esperado

Al finalizar, reporta:

- Lista de archivos creados/modificados.
- Comandos ejecutados (instalación de dependencias, `alembic init`,
  `alembic revision`, `alembic upgrade`).
- Resultado exacto de cada verificación (output de `alembic current`,
  resultado del `curl`, confirmación de las tablas en Supabase).
- Cualquier problema encontrado (error de conexión, credenciales, versión
  de driver, etc.) y cómo se resolvió, o si quedó pendiente.

## Restricciones

- No avanzar a la Etapa 2.
- No implementar funcionalidades fuera del alcance de esta etapa.
- No modificar funcionalidades existentes sin justificación explícita.
- Revisar primero el estado actual del repositorio antes de generar código.
