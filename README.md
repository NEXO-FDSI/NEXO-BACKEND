# NEXO — Backend

Prototype for **AI-driven enrichment of indicators of compromise (IoCs)**, linking them traceably to the MITRE ATT&CK framework and generating auditable reports for a security analyst (SOC tier 1/2).

Course project for **Seminario de Seguridad de la Información 2026-2** — Escuela Colombiana de Ingeniería Julio Garavito.

> Sibling repo: [`nexo-intel-frontend`](https://github.com/NEXO-FDSI/NEXO-FRONTEND.git) — the web interface that consumes this API. They run separately, not as a monorepo.

## Academic context

| | |
|---|---|
| Course | Fundamentos de Seguridad de la Información |
| Group | Group 2 |
| Professor | Diego Alexander López Correa |
| Members | Daniel Alexander Ahumada León · Daniel Ricardo Ruge Gómez · David Alejandro Patacón Henao · David Santiago Cajamarca Cadena |

## Architecture

The backend implements the three layers described in the project proposal:

- **Interface layer** — API built with FastAPI; exposes the endpoints the frontend consumes and records human validation decisions.
- **Processing layer** — six chained modules: `ingestion → normalization → enrichment → correlation → ai_component → reporting`.
- **Persistence layer** — PostgreSQL (Supabase), schema versioned with Alembic; stores indicators, correlation results, reports and a cache of external source responses.

MITRE ATT&CK correlation follows a deliberately two-stage chain:

1. **Entity resolution** — can the indicator be linked to a known entity (malware, campaign, group)?
2. **Technique retrieval** — only if (1) succeeded, the ATT&CK techniques documented for that entity are retrieved.

If stage 1 does not reach sufficient evidence, the pipeline stops there and explicitly declares the absence of an association — it never forces an unsupported technique.

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
        string tipo "malware / group / campaign / tool"
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

Column names are kept in Spanish because they are the actual database columns.

The two link tables mirror the two-stage chain: `indicator_entity_link` records the
**entity resolution** along with its evidence and confidence level, and
`entity_technique_link` is only populated if that resolution succeeded, tracing the
**technique retrieval** back to its ATT&CK source.

The schema is managed with Alembic (`alembic/versions/`), never with `create_all()`.

## Project structure

```
app/
├── ingestion/       # capture and validation of incoming indicators
├── normalization/   # cleanup, dedup, standardization
├── enrichment/       # queries to reputation APIs
├── correlation/     # entity resolution + ATT&CK technique retrieval
├── ai_component/    # LLM + RAG over the ATT&CK knowledge base
├── reporting/        # contextualized report generation
├── api/              # FastAPI endpoints
└── db/                # SQLAlchemy models and PostgreSQL access
data/
├── attck/            # official MITRE ATT&CK STIX/JSON dataset
└── test_dataset/     # curated indicators for the 6 test scenarios
tests/
```

## Prerequisites

- Python 3.14 (latest stable release)
- Docker (optional for local development, required for the final demo)

## Installation

```bash
python3.14 -m venv .venv
source .venv/bin/activate.fish   # fish shell; use activate on bash/zsh
pip install -r requirements.txt
cp .env.example .env
# fill in DATABASE_URL in .env with the Supabase connection string
alembic upgrade head   # creates the tables
```

## Environment variables

| Variable | Description |
|---|---|
| `LLM_API_KEY` | Credential for the language model used by the AI component |
| `REPUTATION_API_KEY` | Credential for the IoC reputation service (enrichment) |
| `DATABASE_URL` | PostgreSQL connection string on Supabase (`postgresql+psycopg://user:password@host:5432/dbname`) |
| `CORS_ORIGINS` | Allowed frontend origins, comma-separated |

## Running in development

```bash
uvicorn app.main:app --reload --port 8000
```

Quick check:
```bash
curl http://localhost:8000/health
# {"status": "ok"}
```

## Docker

```bash
docker build -t threat-intel-backend .
docker run -p 8000:8000 --env-file .env threat-intel-backend
```
