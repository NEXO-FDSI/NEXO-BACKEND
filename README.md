# NEXO — Backend

![Python](https://img.shields.io/badge/Python-3.14-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.141-009688?logo=fastapi&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-D71F00?logo=sqlalchemy&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-4169E1?logo=postgresql&logoColor=white)
![Alembic](https://img.shields.io/badge/migrations-Alembic-6BA539)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Enterprise%2019.1-C8102E)
![Ollama](https://img.shields.io/badge/LLM-Ollama%20qwen3%3A8b-000000?logo=ollama&logoColor=white)
![ChromaDB](https://img.shields.io/badge/vector%20store-ChromaDB-FF6446)
![Docker](https://img.shields.io/badge/Docker-compose-2496ED?logo=docker&logoColor=white)
![pytest](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest&logoColor=white)
![Status](https://img.shields.io/badge/status-9%2F9%20stages%20complete-success)

Prototype for **AI-driven enrichment of indicators of compromise (IoCs)**, linking them traceably to the MITRE ATT&CK framework and generating auditable reports for a security analyst (SOC tier 1/2).

Course project for **Seminario de Seguridad de la Información 2026-2** — Escuela Colombiana de Ingeniería Julio Garavito.

> Sibling repo: [`nexo-intel-frontend`](https://github.com/NEXO-FDSI/NEXO-FRONTEND.git) — the web interface that consumes this API. They run separately, not as a monorepo.

**Status:** all 9 stages of the backend plan are complete. The backend is ready for frontend integration.

## Contents

- [Academic context](#academic-context)
- [What it does](#what-it-does)
- [Architecture](#architecture)
- [Two-stage ATT&CK correlation](#two-stage-attck-correlation)
- [Data model](#data-model)
- [Project structure](#project-structure)
- [Getting started](#getting-started)
- [Environment variables](#environment-variables)
- [Running with Docker](#running-with-docker)
- [API reference](#api-reference)
- [Testing](#testing)
- [Security](#security)
- [Known limitations](#known-limitations)

## Academic context

| | |
|---|---|
| Course | Fundamentos de Seguridad de la Información |
| Group | Group 2 |
| Professor | Diego Alexander López Correa |
| Members | Daniel Alexander Ahumada León · Daniel Ricardo Ruge Gómez · David Alejandro Patacón Henao · David Santiago Cajamarca Cadena |

## What it does

Given an IoC (IP, domain, file hash or URL), the backend:

1. **Ingests** it: normalizes it to one canonical form (refangs `hxxp://`, `[.]`, lowercases, canonical URLs, compressed IPv6), validates the format per type, and rejects duplicates.
2. **Enriches** it with its reputation in [AlienVault OTX](https://otx.alienvault.com/). Responses are cached, so each indicator is queried once.
3. **Correlates** it with MITRE ATT&CK in two deliberately separate stages: first *who* (the entity: malware, group, tool, campaign), and only then *how* (the techniques that entity is documented to use).
4. **Reports** on it: a Markdown report with the evidence, the confidence, the technique table and a short narrative written by an LLM. The narrative is grounded only in the official ATT&CK text of those techniques (RAG).
5. Records the **analyst's validation**: accept or reject, kept as a full audit history.

The system prefers a declared *"no association"* over a guess. If the evidence is insufficient, no ATT&CK technique is attributed.

## Architecture

Three layers, as described in the project proposal:

- **Interface layer**: FastAPI endpoints (`app/api/`), which record human validation decisions.
- **Processing layer**: six chained domain modules. They are pure logic with no dependency on FastAPI, so they can be tested without a server.
- **Persistence layer**: PostgreSQL on Supabase through SQLAlchemy 2.0 (synchronous). The schema is versioned with Alembic.

```mermaid
flowchart LR
    FE["nexo-intel-frontend<br/>(React + Vite)"] -->|HTTP / JSON| API

    subgraph BE["NEXO backend (FastAPI)"]
        API["Interface layer<br/>app/api"]
        subgraph PROC["Processing layer (pure domain modules)"]
            direction LR
            ING[ingestion] --> NOR[normalization] --> ENR[enrichment] --> COR[correlation] --> AI[ai_component] --> REP[reporting]
        end
        DB["Persistence layer<br/>app/db · SQLAlchemy 2.0"]
        API --> PROC
        PROC --> DB
    end

    ENR -->|REST, cached| OTX[("AlienVault OTX")]
    COR -->|parsed once at startup| STIX[("MITRE ATT&CK<br/>STIX 19.1")]
    AI -->|technique texts by ID| CHROMA[("ChromaDB")]
    AI -->|OpenAI-compatible API| LLM[("Ollama<br/>qwen3:8b")]
    DB --> PG[("PostgreSQL<br/>Supabase")]
```

Each step of the pipeline is its own endpoint, and each one requires the previous step:

```mermaid
sequenceDiagram
    actor A as Analyst / frontend
    participant API as FastAPI
    participant OTX as AlienVault OTX
    participant DB as PostgreSQL
    participant V as ChromaDB
    participant L as LLM (Ollama)

    A->>API: POST /indicators {tipo, valor}
    API->>API: normalize + validate (422 / 409)
    API->>DB: INSERT indicators
    API-->>A: 201 indicator

    A->>API: POST /indicators/{id}/enrich
    alt not in enrichment_cache
        API->>OTX: GET /indicators/{section}/{valor}/general
        API->>DB: INSERT enrichment_cache
    end
    API-->>A: 200 {tiene_evidencia, detalle}

    A->>API: POST /indicators/{id}/correlate
    API->>API: (a) entity resolution → (b) techniques, only if (a) succeeded
    API->>DB: entities, indicator_entity_link, entity_technique_link
    API-->>A: 200 {resuelto, entity, confianza, evidencia, tecnicas}

    A->>API: POST /indicators/{id}/report
    opt entity resolved and technique texts found
        API->>V: official text of each technique
        API->>L: grounded prompt
    end
    API->>DB: INSERT reports
    API-->>A: 201 report (Markdown)

    A->>API: POST /reports/{id}/validate {decision}
    API->>DB: INSERT human_validation
    API-->>A: 201 validation
```

The AI component follows the same cut-off principle as the correlation. The LLM is **not called** when no entity was resolved, or when the vector store returns no technique text. If the LLM fails or times out, the report is still generated: every structured part of it is deterministic, and the narrative section states that it is unavailable.

## Two-stage ATT&CK correlation

This is central to the project's design, not an implementation detail:

1. **Entity resolution** (`indicator_entity_link`): can the indicator be linked to a known ATT&CK entity? If there isn't enough evidence, the pipeline stops here and explicitly declares that there is no association.
2. **Technique retrieval** (`entity_technique_link`): runs only if (1) succeeded. It returns the techniques the entity `uses` according to the ATT&CK STIX bundle. An unsupported technique is never forced.

```mermaid
flowchart TD
    A["Cached OTX response"] --> B["Discard aggregated pulses<br/>(more than 1,000 indicators)"]
    B --> C{"Does any malware_families entry<br/>match an ATT&CK entity or alias?"}
    C -- yes --> D["Entity backed by the most pulses<br/>confidence 0.9"]
    C -- no --> E{"Does any tag match?"}
    E -- yes --> F["Entity backed by the most pulses<br/>confidence 0.6"]
    E -- no --> G["resuelto: false<br/>no entity, no techniques — stop"]
    D --> H["Stage (b): techniques the entity 'uses'<br/>in the STIX bundle"]
    F --> H
```

| Rule | Why |
|---|---|
| Only `malware_families[].display_name` (0.9) and `tags[]` (0.6) are candidates. The free-text pulse `name` is never used | Structured signals are preferred over noisy ones. Free text is the most direct route to a wrong attribution |
| Pulses with more than **1,000 indicators** are ignored | These are aggregated dumps, not focused reports. On real OTX data (Stage 9), one dump was enough to attribute a WannaCry sample to Cobalt Strike with 0.9 confidence. The focused reports measured had between 3 and 378 indicators |
| Within a tier, the entity backed by **the most distinct pulses** wins. Ties go to the first entity seen | A single noisy pulse cannot outvote several consistent reports |
| Names that ATT&CK shares across types (e.g. a group and a malware) are merged, and the evidence says so | The ambiguity is recorded instead of being hidden |

The evidence string keeps the full trace, for example: `pulse_info.pulses[].malware_families[].display_name = 'WannaCry' (respaldado por 2 pulse(s); 1 pulse(s) masivo(s) descartado(s))`.

## Data model

```mermaid
erDiagram
    indicators ||--o{ enrichment_cache : "caches responses for"
    indicators ||--o{ indicator_entity_link : "stage (a)"
    entities   ||--o{ indicator_entity_link : "stage (a)"
    entities   ||--o{ entity_technique_link : "stage (b)"
    techniques ||--o{ entity_technique_link : "stage (b)"
    indicators ||--o{ reports : "generates"
    reports    ||--o{ human_validation : "is validated by"

    indicators {
        int id PK
        string tipo "ip / domain / hash / url"
        string valor UK
        string fuente
        timestamptz timestamp_ingesta
    }
    enrichment_cache {
        int id PK
        int indicator_id FK
        string fuente_api
        text respuesta_json
        timestamptz timestamp
    }
    entities {
        int id PK
        string nombre
        string tipo "malware / grupo / herramienta / campaña"
    }
    indicator_entity_link {
        int id PK
        int indicator_id FK
        int entity_id FK
        text evidencia
        float confianza "0.0 - 1.0"
    }
    techniques {
        string id PK "official MITRE id, e.g. T1566"
        string nombre
        string tactica
    }
    entity_technique_link {
        int id PK
        int entity_id FK
        string technique_id FK
        string fuente_attck
    }
    reports {
        int id PK
        int indicator_id FK
        text contenido
        float nivel_confianza
        timestamptz timestamp
    }
    human_validation {
        int id PK
        int report_id FK
        string decision "aceptado / rechazado"
        string analista
        timestamptz timestamp
    }
```

Column names are in Spanish because they are the actual database columns. The schema is managed only by Alembic (`alembic/versions/`), never with `create_all()`. The one exception is the ephemeral test database.

## Project structure

```
app/
├── api/              # FastAPI routers (interface layer)
├── core/config.py    # centralized settings (pydantic-settings)
├── ingestion/        # format validation per indicator type
├── normalization/    # refang, canonical forms, dedup key
├── enrichment/       # AlienVault OTX client + cache
├── correlation/      # ATT&CK STIX index + two-stage correlation
├── ai_component/     # LLM client, grounded prompt, vector store (Chroma)
├── reporting/        # fixed report template + orchestration
├── db/               # SQLAlchemy models, session, repositories
├── schemas/          # Pydantic request/response models
└── main.py           # app, lifespan, CORS, global error handler
alembic/              # migrations
scripts/              # seed_techniques, seed_technique_embeddings
data/
├── attck/            # MITRE ATT&CK STIX bundle (downloaded, git-ignored)
├── chroma/           # persisted vector store (generated, git-ignored)
└── test_dataset/     # frozen real OTX responses + ATT&CK subset for the 6 scenarios
tests/                # pytest suite (runs against a local Docker Postgres)
```

## Getting started

### Prerequisites

- Python 3.14
- Docker (the test database; optionally the backend itself)
- [Ollama](https://ollama.com/) with `qwen3:8b` and `nomic-embed-text`. A GPU is strongly recommended (see [Known limitations](#known-limitations))
- A PostgreSQL database (Supabase) and an [AlienVault OTX](https://otx.alienvault.com/) API key

### Local setup

```bash
python3.14 -m venv .venv
source .venv/bin/activate.fish   # fish shell; use .venv/bin/activate on bash/zsh
pip install -r requirements.txt

cp .env.example .env             # fill in DATABASE_URL and REPUTATION_API_KEY

# MITRE ATT&CK Enterprise 19.1 bundle (~50 MB, git-ignored)
curl -L -o data/attck/enterprise-attack-19.1.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.1.json

alembic upgrade head             # create the tables in Supabase

ollama pull qwen3:8b
ollama pull nomic-embed-text
python -m scripts.seed_techniques            # optional: correlation also creates techniques on demand
python -m scripts.seed_technique_embeddings  # required for the narrative analysis (idempotent)

uvicorn app.main:app --reload --port 8000
```

Quick check:

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

Interactive documentation: Swagger UI at <http://localhost:8000/docs> (endpoints grouped by tag in pipeline order), and ReDoc at <http://localhost:8000/redoc>.

## Environment variables

All settings are read in `app/core/config.py` (pydantic-settings), from `.env` or the environment.

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_URL` | yes | — | PostgreSQL on Supabase: `postgresql+psycopg://user:password@host:5432/dbname` |
| `REPUTATION_API_KEY` | for `/enrich` | `""` | AlienVault OTX API key |
| `CORS_ORIGINS` | yes, for the frontend | `""` | Allowed origins, comma-separated (e.g. `http://localhost:5173`). `*` is rejected at startup |
| `TEST_DATABASE_URL` | for tests | `""` | Local Docker Postgres: `postgresql+psycopg://postgres:test@localhost:5433/nexo_test`. Must point to localhost |
| `ATTCK_STIX_PATH` | no | `data/attck/enterprise-attack-19.1.json` | ATT&CK STIX bundle, loaded once at startup |
| `LLM_BASE_URL` | no | `http://localhost:11434/v1` | OpenAI-compatible endpoint (Ollama in development) |
| `LLM_API_KEY` | no | `ollama` | LLM credential (Ollama ignores it; set it when switching to a hosted API) |
| `LLM_MODEL` | no | `qwen3:8b` | Model that writes the narrative analysis |
| `EMBEDDING_MODEL` | no | `nomic-embed-text` | Model used to seed the technique embeddings |
| `CHROMA_PERSIST_DIR` | no | `./data/chroma` | Where the vector store is persisted |

## Running with Docker

```bash
docker compose up --build -d
curl http://localhost:8000/health   # {"status":"ok"}
docker compose down
```

`docker-compose.yml` builds the image from the `Dockerfile` and injects `.env` at runtime. The secrets are **not** in the image: `.dockerignore` excludes `.env`. The compose file also does two things:

- It points `LLM_BASE_URL` at the host's Ollama (`host.docker.internal`). For the container to reach it, Ollama must listen on all interfaces: `OLLAMA_HOST=0.0.0.0 ollama serve`.
- It mounts `./data/chroma` so the container uses the embeddings seeded on the host.

The ATT&CK bundle in `data/attck/` is copied into the image, so download it before building. The test database has its own compose file and project (`docker-compose.test.yml`), and the two stacks don't interfere.

Without compose:

```bash
docker build -t nexo-intel-backend .
docker run -p 8000:8000 --env-file .env nexo-intel-backend
```

## API reference

Every error response is JSON with a `detail` field.

| Method | Path | Tag | Requires | Success | Errors |
|---|---|---|---|---|---|
| POST | `/indicators` | Indicators | — | 201 | 409 duplicate · 422 invalid format |
| POST | `/indicators/{id}/enrich` | Enrichment | indicator | 200 | 404 · 502 OTX unavailable |
| POST | `/indicators/{id}/correlate` | Correlation | `/enrich` | 200 | 400 not enriched · 404 |
| POST | `/indicators/{id}/report` | Reports | `/enrich` | 201 | 400 not enriched · 404 |
| POST | `/reports/{id}/validate` | Reports | report | 201 | 404 · 422 invalid decision |
| GET | `/health` | Health | — | 200 | — |

The examples below are real responses for a WannaCry sample (scenario 1 of the test dataset), with the LLM running locally.

### `POST /indicators` — register an indicator

```bash
curl -X POST http://localhost:8000/indicators \
  -H 'Content-Type: application/json' \
  -d '{"tipo": "hash", "valor": "24D004A104D4D54034DBCFFC2A4B19A11F39008A575AA614EA04703480B1022C", "fuente": "reporte interno SOC"}'
```

```json
{
  "tipo": "hash",
  "valor": "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
  "fuente": "reporte interno SOC",
  "id": 1,
  "timestamp_ingesta": "2026-09-22T17:51:20.169333Z"
}
```

`tipo` is one of `ip`, `domain`, `hash` (MD5, SHA-1, SHA-256), `url`. Defanged values (`hxxp://evil[.]com`) are accepted and stored in canonical form. `fuente` is optional.

### `POST /indicators/{id}/enrich` — reputation in AlienVault OTX

```bash
curl -X POST http://localhost:8000/indicators/1/enrich
```

```json
{
  "indicator_id": 1,
  "fuente": "alienvault_otx",
  "tiene_evidencia": true,
  "detalle": {
    "indicator": "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c",
    "type": "sha256",
    "pulse_info": { "count": 50, "pulses": ["… raw OTX pulses …"] }
  }
}
```

`detalle` is the raw OTX response (abbreviated here). A **502** means *"could not verify"*, which is never presented as *"no evidence"*.

### `POST /indicators/{id}/correlate` — two-stage correlation

```bash
curl -X POST http://localhost:8000/indicators/1/correlate
```

```json
{
  "indicator_id": 1,
  "resuelto": true,
  "entity": { "id": 1, "nombre": "wannacry", "tipo": "malware" },
  "confianza": 0.9,
  "evidencia": "pulse_info.pulses[].malware_families[].display_name = 'WannaCry' (respaldado por 2 pulse(s); 1 pulse(s) masivo(s) descartado(s))",
  "tecnicas": [
    { "id": "T1210", "nombre": "Exploitation of Remote Services", "tactica": "Lateral Movement" },
    { "id": "T1489", "nombre": "Service Stop", "tactica": "Impact" },
    { "id": "T1486", "nombre": "Data Encrypted for Impact", "tactica": "Impact" }
  ]
}
```

Abbreviated: this entity has 16 techniques. Without enough evidence, the response is `{"resuelto": false, "entity": null, "confianza": null, "evidencia": null, "tecnicas": []}`.

### `POST /indicators/{id}/report` — generate the report

```bash
curl -X POST http://localhost:8000/indicators/1/report
```

```json
{
  "indicator_id": 1,
  "contenido": "# Informe de indicador: 24d004a1…\n\n**Tipo:** hash\n…",
  "nivel_confianza": 0.9,
  "id": 1,
  "timestamp": "2026-09-22T17:51:39.361866Z"
}
```

`contenido` is Markdown. Excerpt:

```markdown
## Resolución de entidad y técnicas ATT&CK

- **Entidad asociada:** wannacry (malware)
- **Evidencia de asociación:** pulse_info.pulses[].malware_families[].display_name = 'WannaCry' (respaldado por 2 pulse(s); 1 pulse(s) masivo(s) descartado(s))
- **Confianza de la asociación:** 0.9

### Técnicas documentadas

| ID | Técnica | Táctica |
|---|---|---|
| T1210 | Exploitation of Remote Services | Lateral Movement |
| T1489 | Service Stop | Impact |
| T1486 | Data Encrypted for Impact | Impact |
| … | … | … |

## Análisis

El hash proporcionado está asociado al malware Wannacry debido a que se identificó como parte de su familia de malware en los registros de detección. Las técnicas asociadas, como la encriptación de datos (T1486) y la explotación de servicios remotos (T1210), son típicas de Wannacry, que se utiliza para bloquear accesos a datos y moverse dentro de una red. […]

## Estado de validación

Pendiente de revisión humana.
```

### `POST /reports/{id}/validate` — analyst decision

```bash
curl -X POST http://localhost:8000/reports/1/validate \
  -H 'Content-Type: application/json' \
  -d '{"decision": "aceptado", "analista": "analista SOC N1"}'
```

```json
{
  "report_id": 1,
  "decision": "aceptado",
  "analista": "analista SOC N1",
  "id": 1,
  "timestamp": "2026-09-22T17:51:39.380001Z"
}
```

`decision` is `aceptado` or `rechazado`. `analista` is optional. Each call adds a row, so the history of decisions is preserved.

## Testing

Tests never touch Supabase or the network. They run against an ephemeral Postgres in Docker. `conftest.py` refuses any `TEST_DATABASE_URL` that isn't localhost, and each test runs inside a transaction that is rolled back. OTX and the LLM are always mocked. A guard fixture fails any test that reaches the real LLM.

```bash
docker compose -f docker-compose.test.yml up -d --wait   # Postgres on :5433
pytest -v                                                # full suite
pytest -v tests/test_e2e_scenarios.py                    # the 6 official scenarios
pytest tests/test_correlation.py::test_pulse_masivo_no_aporta_candidatos   # a single test
docker compose -f docker-compose.test.yml down
```

If `TEST_DATABASE_URL` isn't set, the database tests are **skipped**, not failed.

### The six official scenarios (proposal, section 5.1)

`tests/test_e2e_scenarios.py` runs the whole pipeline over HTTP (ingest → enrich → correlate → report, plus validate for scenario 6) for each scenario:

- **OTX responses**: real responses captured from OTX on 2026-09-22 and frozen in `data/test_dataset/scenarios.json`. Each pulse is trimmed to the fields the pipeline reads; no pulse is removed.
- **ATT&CK index**: a real subset frozen in `data/test_dataset/attck_subset.json`, holding every entity that any candidate in those responses resolves to. The result is therefore identical to using the full bundle, and `test_subset_equivale_al_bundle_real` checks that whenever the bundle is present.
- **Reproducibility**: the scenarios run offline on a fresh clone.

| # | Scenario | Real input | Result |
|---|---|---|---|
| 1 | Known threat | WannaCry sample SHA-256 (AlienVault *WannaCry Indicators*) | `wannacry` · 0.9 · 16 techniques |
| 2 | Incomplete information | Residential IP with no OTX pulses | `resuelto: false` · confidence 0.0 · no techniques |
| 3 | Multiple techniques | Phishing domain (Lazarus) + payload hash (Remcos) + C2 IP (Dridex) | three distinct entities and technique sets, covering many tactics |
| 4 | Same campaign | SUNBURST DLL hash + `ervsystem.com` (SolarWinds report) | both resolve to `sunburst` · shared techniques |
| 5 | Benign indicator | `8.8.8.8` (whitelisted by OTX) | `resuelto: false` · no techniques · no LLM call |
| 6 | Incorrect association | SUNBURST DLL SHA-256 whose only remaining match is a `blackcat` tag in a 185-tag pulse | low-confidence (0.6) BlackCat hypothesis → the analyst **rejects** it and the rejection is persisted |

## Security

This is a prototype, but the essential measures are in place and verified:

| Check | How it is enforced / verified |
|---|---|
| No `*` in CORS | Explicit origins only. `Settings` refuses to start if `CORS_ORIGINS` contains `*` (with credentials enabled, `*` would expose the API to any site) |
| `.env` never committed | Git-ignored. `git log --all --full-history -- .env` is empty |
| Secrets stay out of the image | `.dockerignore` excludes `.env` and `.venv`, and `.env` is injected at runtime |
| No hardcoded credentials | Everything comes from environment variables. The real `.env` values do not appear in any file in the repository |
| No secrets in logs | Nothing logs `Settings` or the environment. SQLAlchemy masks passwords in connection URLs |
| No internal details in errors | A global handler turns any unhandled exception into `500 {"detail": "Error interno del servidor"}`. The traceback goes only to the server log. Intentional `HTTPException`s (400/404/409/502) and validation errors (422) pass through unchanged |
| Input validation | Pydantic schemas; every indicator is validated after normalization |
| Large data out of git | `data/attck/*.json` and `data/chroma/` are git-ignored |
| Tests can't hit production | `TEST_DATABASE_URL` must be localhost and different from `DATABASE_URL` |

## Known limitations

- **No authentication or multi-user support.** This is by design: the proposal excludes it from the prototype's scope. There is also no rate limiting.
- **A 500 response has no CORS headers.** Starlette's `ServerErrorMiddleware` sits outside `CORSMiddleware`, so in the browser an unhandled error looks like a CORS/network error. The server log still has the details.
- **LLM latency.** The narrative call has a 60 s timeout with no retries (`TIMEOUT` in `app/ai_component/llm_client.py`), so generating a report can take up to about a minute. Measured with `qwen3:8b`: 23–30+ s on CPU, versus about 4 s on an RTX 4060 (about 10 s when the model has to be loaded first). If the model doesn't answer in time, the report still comes out, without the narrative section. Run Ollama on a GPU (on Arch/CachyOS: `sudo pacman -Syu ollama-cuda`, then `sudo systemctl restart ollama`; `ollama ps` should show `100% GPU`), or point `LLM_BASE_URL` at a hosted model.
- **The correlation is a heuristic over community data.** Discarding mass pulses and voting by support fix the aggregator hijacking seen on real OTX data, but noise remains:
  - a generic family label such as `Wiper` matches the specific ATT&CK malware *Wiper*;
  - a tag list that mixes threats can produce a wrong hypothesis, as in scenario 6.

  Human validation is the designed safeguard against both.
