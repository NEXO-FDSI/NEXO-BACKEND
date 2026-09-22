# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# NEXO-BACKEND

Backend (FastAPI) del proyecto de enriquecimiento de indicadores de
compromiso con IA — Seminario de Seguridad de la Información 2026-2,
Grupo 2, Escuela Colombiana de Ingeniería Julio Garavito. El frontend
(`nexo-intel-frontend`) es un repo aparte, no monorepo.

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
- IA: LLM vía cliente `openai` apuntando a Ollama local por defecto
  (`qwen3:8b`, embeddings `nomic-embed-text`); vector store Chroma
  persistido en `data/chroma/`.

## Comandos

Shell del usuario: fish (`source .venv/bin/activate.fish`).

```bash
pip install -r requirements.txt
alembic upgrade head                          # aplica migraciones (Supabase)
alembic revision --autogenerate -m "..."      # nueva migración
uvicorn app.main:app --reload --port 8000     # dev; Swagger en /docs

docker compose -f docker-compose.test.yml up -d   # Postgres de tests en :5433
pytest                                            # suite completa
pytest tests/test_correlation.py::test_nombre     # un solo test
pytest -v tests/test_e2e_scenarios.py             # los 6 escenarios oficiales

docker compose up --build -d                  # stack completo (backend) en :8000
docker compose down

python -m scripts.seed_techniques             # llena tabla techniques desde el STIX
python -m scripts.seed_technique_embeddings   # siembra Chroma (requiere Ollama)
```

- Los tests se **saltan** (no fallan) si `TEST_DATABASE_URL` no está en
  `.env`; `conftest.py` además aborta si apunta a algo distinto de
  localhost o coincide con `DATABASE_URL`.
- El arranque de la app requiere el bundle STIX
  `data/attck/enterprise-attack-19.1.json` (~50 MB, en `.gitignore`);
  se carga una vez en el `lifespan` de `app/main.py`.
- `test.py` en la raíz es un smoke test manual de Ollama + Chroma, no
  parte de la suite de pytest.

## Arquitectura

Tres capas:
- **Interfaz** — FastAPI, endpoints en `app/api/`.
- **Procesamiento** — módulos de dominio en
  `app/{ingestion,normalization,enrichment,correlation,ai_component,reporting}/`,
  lógica pura sin depender de FastAPI (para poder testearse sin levantar
  servidor).
- **Persistencia** — `app/db/` (modelos, repositorios, sesión) y
  `app/schemas/` (Pydantic por tabla).

Flujo del pipeline, un endpoint por paso (cada uno exige el anterior):

1. `POST /indicators` — el `model_validator` de `IndicatorCreate` primero
   normaliza (refang, canonización) y luego valida el valor ya canónico
   (formato inválido → 422); duplicado → 409 por la restricción única.
2. `POST /indicators/{id}/enrich` — consulta OTX y guarda la respuesta en
   `enrichment_cache`. Si la API falla → 502, nunca un 200 "sin evidencia".
3. `POST /indicators/{id}/correlate` — correlación determinística contra
   el índice ATT&CK a partir del enriquecimiento cacheado (400 si no
   existe).
4. `POST /indicators/{id}/report` — correlación + análisis del LLM
   grounded en los textos de técnicas recuperados de Chroma.
5. `POST /reports/{id}/validate` — validación humana; cada decisión es
   una fila nueva (historial auditable).

La correlación con MITRE ATT&CK sigue una cadena de **dos etapas
deliberadamente separadas** — esto es central al diseño del proyecto, no
un detalle de implementación:

1. **Resolución de entidad** (tabla `indicator_entity_link`) — si no hay
   evidencia suficiente, el pipeline se corta aquí.
2. **Recuperación de técnicas** (tabla `entity_technique_link`) — solo se
   ejecuta si la etapa 1 tuvo éxito. Nunca forzar una técnica ATT&CK sin
   sustento.

Reglas de la etapa (a), en `app/correlation/service.py`:
- Candidatos: solo `malware_families` (0.9) y luego `tags` (0.6); nunca
  el `name` del pulse.
- Se ignoran los pulses con más de `MAX_INDICADORES_PULSE` (1.000)
  indicadores: son volcados agregados.
- Dentro de cada nivel gana la entidad respaldada por más pulses
  distintos.

La razón (hallazgo de la Etapa 9 con datos reales de OTX): un solo volcado
agregado atribuía un hash de WannaCry a Cobalt Strike con 0.9.

El componente de IA (`app/ai_component/service.py`) replica ese corte: no
llama al LLM si no hay entidad resuelta ni si el vector store no devuelve
textos, y si el LLM falla el informe se genera igual (el resto es
determinístico).

### Convenciones que no son obvias

- Los repositorios solo hacen `flush`; el `commit`/`rollback` lo hace el
  endpoint.
- El índice ATT&CK y el vector store viven en `app.state` (lifespan) y se
  inyectan con `get_attck_index` / `get_vector_store`. En tests el
  lifespan no corre: `conftest.py` sobreescribe esas dependencias con un
  índice sintético (técnicas `T900x`) y un `FakeVectorStore`.
- Un fixture autouse en `conftest.py` hace fallar cualquier test que
  llame al LLM real; los tests que lo necesitan parchean
  `app.ai_component.service.generate_analysis`.
- Cada test corre en una transacción con rollback
  (`join_transaction_mode="create_savepoint"`), así que los `commit()`
  de los endpoints no persisten entre tests.
- `scripts/seed_technique_embeddings.py` reutiliza los helpers privados
  de filtrado de `attck_loader` a propósito, para que Chroma y el índice
  de correlación contengan exactamente las mismas técnicas.
- Nombres de columnas y mucho del código están en español (son las
  columnas reales de la BD); mantener esa convención.
- `tests/test_e2e_scenarios.py` usa respuestas reales de OTX congeladas
  (`data/test_dataset/scenarios.json`) y un subconjunto real de ATT&CK
  (`attck_subset.json`): toda entidad a la que resuelva algún candidato
  no descartado de esas respuestas, con sus alias y técnicas. Si se
  cambia `scenarios.json` hay que regenerar el subconjunto;
  `test_subset_equivale_al_bundle_real` lo detecta cuando el bundle está
  presente.
- El handler global de `Exception` en `app/main.py` responde un 500
  genérico. Starlette re-lanza la excepción después, así que para ver esa
  respuesta en un test hace falta `TestClient(app, raise_server_exceptions=False)`.

## Roadmap y estado

Plan completo de 9 etapas en `docs/PlanBackendNexo.md`. Prompt detallado
de cada etapa en `docs/stages/etapaNN.md`. Las 9 etapas están
completas: el backend está listo para la integración con el frontend.

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
