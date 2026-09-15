# Etapa 2 — Capa de acceso a datos y schemas Pydantic

## Contexto

Backend (FastAPI) del proyecto de enriquecimiento de inteligencia de
amenazas. La Etapa 1
ya está completa: existe `app/core/config.py` (pydantic-settings),
`app/db/database.py` (engine, `SessionLocal`, `Base`, `get_db`),
`app/db/models.py` con las 8 tablas SQLAlchemy (`Indicator`,
`EnrichmentCache`, `Entity`, `IndicatorEntityLink`, `Technique`,
`EntityTechniqueLink`, `Report`, `HumanValidation`), y Alembic con la
migración inicial ya aplicada contra PostgreSQL en Supabase.

Todavía no existe ningún endpoint de negocio (solo `/health`), ni capa de
repositorios, ni schemas Pydantic, ni tests.

## Objetivo

Construir una capa de acceso a datos con repositorios CRUD básicos y
schemas Pydantic (request/response) para las 8 entidades, con tests
unitarios que corran contra un PostgreSQL local en Docker — **no contra
Supabase**.

## Alcance

- Un schema Pydantic `Base` / `Create` / `Read` por cada una de las 8
  entidades, en `app/schemas/`.
- Un repositorio genérico reutilizable (`BaseRepository`) instanciado por
  cada entidad en `app/db/repositories/`, con `create`, `get` (por id) y
  `list`.
- Un PostgreSQL local en Docker exclusivo para tests (no Supabase).
- Tests unitarios de create/get/list para cada una de las 8 entidades.

## Fuera de alcance

- No crear endpoints FastAPI para estas entidades (eso empieza en la
  Etapa 3, con el módulo de ingesta).
- No implementar lógica de negocio: validación de formato de indicador,
  deduplicación, resolución de entidad, etc.
- No modificar el esquema de las 8 tablas ni las migraciones de Alembic ya
  aplicadas en la Etapa 1.
- No tocar el frontend.
- No usar la base de datos de Supabase para nada relacionado con tests.

## Esquema de schemas por entidad (referencia obligatoria)

Los campos de `Base` (compartidos por `Create` y `Read`) y los campos
adicionales que solo lleva `Read` (los que genera la base de datos):

| Entidad | Campos en `Base`/`Create` | Campos extra en `Read` |
|---|---|---|
| Indicator | `tipo: str`, `valor: str`, `fuente: str \| None` | `id: int`, `timestamp_ingesta: datetime` |
| EnrichmentCache | `indicator_id: int`, `fuente_api: str`, `respuesta_json: str` | `id: int`, `timestamp: datetime` |
| Entity | `nombre: str`, `tipo: str` | `id: int` |
| IndicatorEntityLink | `indicator_id: int`, `entity_id: int`, `evidencia: str \| None`, `confianza: float` | `id: int` |
| Technique | `id: str`, `nombre: str`, `tactica: str` | — (el `id` ya va en `Base`, no es autoincrement) |
| EntityTechniqueLink | `entity_id: int`, `technique_id: str`, `fuente_attck: str \| None` | `id: int` |
| Report | `indicator_id: int`, `contenido: str`, `nivel_confianza: float` | `id: int`, `timestamp: datetime` |
| HumanValidation | `report_id: int`, `decision: str`, `analista: str \| None` | `id: int`, `timestamp: datetime` |

Todos los schemas `Read` deben usar Pydantic v2 con
`model_config = ConfigDict(from_attributes=True)` para poder construirse
directamente desde los objetos ORM.

## Tareas

1. Revisar el estado actual del repositorio: confirmar que
   `app/core/config.py`, `app/db/database.py`, `app/db/models.py` y
   Alembic ya existen y funcionan (Etapa 1 completa) antes de escribir
   nada nuevo.
2. Crear `app/schemas/` con un archivo por entidad (`indicator.py`,
   `enrichment_cache.py`, `entity.py`, `indicator_entity_link.py`,
   `technique.py`, `entity_technique_link.py`, `report.py`,
   `human_validation.py`), cada uno con sus clases `*Base`, `*Create`,
   `*Read` según la tabla de la sección anterior.
3. Crear `app/db/repositories/base.py` con una clase genérica
   `BaseRepository` (usando `Generic`/`TypeVar`) que reciba el modelo
   SQLAlchemy en el constructor y exponga:
   - `create(db: Session, obj_in: dict) -> ModelType`
   - `get(db: Session, id) -> ModelType | None`
   - `list(db: Session, skip: int = 0, limit: int = 100) -> list[ModelType]`
   Los repositorios NO deben crear su propia sesión — siempre reciben la
   `Session` como parámetro (inyectada desde donde se use).
4. Crear `app/db/repositories/` con un archivo por entidad, cada uno
   instanciando `BaseRepository` con su modelo correspondiente (ej.
   `indicator_repository = BaseRepository[Indicator](Indicator)`).
5. Configurar un PostgreSQL local en Docker exclusivo para tests: agregar
   `docker-compose.test.yml` con un servicio `postgres:16`, puerto
   `5433:5432` (evitar chocar con cualquier Postgres local existente),
   variables `POSTGRES_PASSWORD=test`, `POSTGRES_DB=nexo_test`.
6. Agregar `TEST_DATABASE_URL` a `.env.example` con el formato
   `postgresql+psycopg://postgres:test@localhost:5433/nexo_test`.
7. Crear `tests/conftest.py` con un fixture de sesión de test que:
   - Se conecte a `TEST_DATABASE_URL` (nunca a `DATABASE_URL` de
     Supabase — validar explícitamente que apunte a `localhost`).
   - Cree las tablas con `Base.metadata.create_all()` al inicio de la
     sesión de tests (esto es válido únicamente para la base de datos de
     test efímera — nunca contra Supabase, donde Alembic sigue siendo la
     única fuente de verdad).
   - Elimine las tablas con `Base.metadata.drop_all()` al finalizar.
   - Provea una `Session` limpia por test (rollback o recreación entre
     tests, para que no dependan del orden de ejecución).
8. Escribir `tests/test_repositories.py` con al menos un test de
   `create`, `get` y `list` por cada una de las 8 entidades (24 tests
   mínimo, pueden agruparse con `pytest.mark.parametrize` si reduce
   duplicación significativamente).

## Reglas de implementación

- Pydantic v2 (`BaseModel`, `ConfigDict`), consistente con FastAPI moderno.
- Un solo `BaseRepository` genérico — no dupliques la lógica de CRUD en
  cada una de las 8 clases.
- Los repositorios reciben la `Session` por parámetro, nunca la crean ni
  la importan como singleton global.
- Ningún test debe tocar la base de datos de Supabase bajo ninguna
  circunstancia — verificar esto explícitamente en el fixture.
- No agregues dependencias nuevas fuera de lo ya instalado (no se
  necesita nada adicional para esta etapa).
- No crees endpoints FastAPI en esta etapa.

## Verificación

```bash
docker compose -f docker-compose.test.yml up -d
pytest -v tests/
```

- Los 24+ tests deben pasar en verde.
- Revisar `tests/conftest.py` y confirmar que `TEST_DATABASE_URL` apunta a
  `localhost:5433`, nunca al host de Supabase.
- Confirmar que después de correr la suite, `docker compose -f
  docker-compose.test.yml down` deja todo limpio (no hay estado
  persistente esperado entre corridas, salvo que se agregue un volumen
  explícitamente — si se agrega, documentar por qué).
- El endpoint `/health` sigue respondiendo igual que antes (no se tocó).

## Criterios de aceptación

- Cada una de las 8 tablas tiene su schema `Base`/`Create`/`Read` y su
  repositorio correspondiente.
- Los tests corren contra Postgres local en Docker, no contra Supabase, y
  pasan todos en verde.
- No se agregó ningún endpoint de negocio nuevo.
- No se implementó ninguna lógica de negocio (dedup, validación de
  formato, resolución de entidad) — solo acceso a datos genérico.

## Resultado esperado

Al finalizar, reporta:

- Lista de archivos creados.
- Comando usado para levantar el Postgres de test y resultado.
- Output completo de `pytest -v`.
- Confirmación explícita de que ningún test tocó Supabase.
- Cualquier problema encontrado y cómo se resolvió, o si quedó pendiente.

## Restricciones

- No avanzar a la Etapa 3.
- No implementar funcionalidades fuera del alcance de esta etapa.
- No modificar el esquema de las 8 tablas ni las migraciones existentes.
- Revisar primero el estado actual del repositorio antes de generar código.