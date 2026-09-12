# NEXO — Backend

Prototipo de **enriquecimiento de indicadores de compromiso (IoC) mediante IA**, que los relaciona de forma trazable con el marco MITRE ATT&CK y genera informes auditables para un analista de seguridad (SOC nivel 1/2).

Proyecto del curso **Seminario de Seguridad de la Información 2026-2** — Escuela Colombiana de Ingeniería Julio Garavito.

> Repo hermano: [`nexo-intel-frontend`](https://github.com/NEXO-FDSI/NEXO-FRONTEND.git) — interfaz web que consume esta API. Se ejecutan por separado, no como monorepo.

## Contexto académico

| | |
|---|---|
| Asignatura | Fundamentos de Seguridad de la Información |
| Grupo | Grupo 2 |
| Profesor | Diego Alexander López Correa |
| Integrantes | Daniel Alexander Ahumada León · Daniel Ricardo Ruge Gómez · David Alejandro Patacón Henao · David Santiago Cajamarca Cadena |

## Arquitectura

El backend implementa las tres capas descritas en la propuesta del proyecto:

- **Capa de interfaz** — API construida con FastAPI, expone los endpoints que consume el frontend y registra las decisiones de validación humana.
- **Capa de procesamiento** — seis módulos encadenados: `ingestion → normalization → enrichment → correlation → ai_component → reporting`.
- **Capa de persistencia** — SQLite, almacena indicadores, resultados de correlación, informes y caché de respuestas de fuentes externas.

La correlación con MITRE ATT&CK sigue una cadena de dos etapas deliberadamente separadas:

1. **Resolución de entidad** — ¿el indicador puede vincularse a una entidad conocida (malware, campaña, grupo)?
2. **Recuperación de técnicas** — solo si (1) tuvo éxito, se recuperan las técnicas ATT&CK documentadas para esa entidad.

Si la etapa 1 no alcanza evidencia suficiente, el pipeline corta ahí y declara explícitamente la ausencia de asociación — nunca fuerza una técnica sin sustento.

## Estructura del proyecto

```
app/
├── ingestion/       # captura y validación de indicadores de entrada
├── normalization/   # limpieza, dedup, estandarización
├── enrichment/       # consultas a APIs de reputación
├── correlation/     # resolución de entidad + recuperación de técnicas ATT&CK
├── ai_component/    # LLM + RAG sobre la base de conocimiento ATT&CK
├── reporting/        # generación del informe contextualizado
├── api/              # endpoints FastAPI
└── db/                # modelos y acceso a SQLite
data/
├── attck/            # dataset STIX/JSON oficial de MITRE ATT&CK
└── test_dataset/     # indicadores curados para los 6 escenarios de prueba
tests/
```

## Requisitos previos

- Python 3.14 (última versión estable)
- Docker (opcional para desarrollo local, requerido para la demo final)

## Instalación

```bash
python3.14 -m venv .venv
source .venv/bin/activate.fish   # fish shell; usa activate si estás en bash/zsh
pip install -r requirements.txt
cp .env.example .env
```

## Variables de entorno

| Variable | Descripción |
|---|---|
| `LLM_API_KEY` | Credencial del modelo de lenguaje usado en el componente de IA |
| `REPUTATION_API_KEY` | Credencial del servicio de reputación de IoCs (enriquecimiento) |
| `DB_PATH` | Ruta del archivo SQLite (default `./data/app.db`) |
| `CORS_ORIGINS` | Orígenes permitidos para el frontend, separados por coma |

## Ejecución en desarrollo

```bash
uvicorn app.main:app --reload --port 8000
```

Verificación rápida:
```bash
curl http://localhost:8000/health
# {"status": "ok"}
```

## Docker

```bash
docker build -t threat-intel-backend .
docker run -p 8000:8000 --env-file .env threat-intel-backend
```
