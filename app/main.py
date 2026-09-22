import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.ai_component.vectorstore import ChromaVectorStore
from app.api import correlation, enrichment, indicators, reports
from app.correlation.attck_loader import load_attck_index
from app.core.config import settings

logger = logging.getLogger(__name__)

DESCRIPCION = """
Enriquecimiento de indicadores de compromiso (IP, dominio, hash, URL) con correlación
trazable a MITRE ATT&CK e informes auditables para un analista SOC.

**Flujo** — cada paso requiere el anterior:

1. `POST /indicators` — ingesta, normalización y validación.
2. `POST /indicators/{id}/enrich` — reputación en AlienVault OTX (con caché).
3. `POST /indicators/{id}/correlate` — resolución de entidad y, solo si hubo, técnicas ATT&CK.
4. `POST /indicators/{id}/report` — informe con análisis narrativo grounded (LLM + RAG).
5. `POST /reports/{id}/validate` — aceptación o rechazo por un analista.

Prototipo académico: sin autenticación por diseño (Seminario de Seguridad de la
Información 2026-2, Grupo 2, Escuela Colombiana de Ingeniería Julio Garavito).
"""

TAGS = [
    {"name": "Indicators", "description": "Ingesta de indicadores de compromiso."},
    {"name": "Enrichment", "description": "Reputación del indicador en AlienVault OTX."},
    {"name": "Correlation", "description": "Cadena de dos etapas contra MITRE ATT&CK."},
    {"name": "Reports", "description": "Informe del indicador y validación humana."},
    {"name": "Health", "description": "Estado del servicio."},
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    # El bundle STIX se parsea una sola vez por proceso, nunca por request.
    app.state.attck_index = load_attck_index(settings.ATTCK_STIX_PATH)
    app.state.vector_store = ChromaVectorStore()
    yield


app = FastAPI(
    title="NEXO Intel API",
    description=DESCRIPCION,
    version="1.0.0",
    openapi_tags=TAGS,
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def error_no_manejado(request: Request, exc: Exception) -> JSONResponse:
    """Último recurso: el detalle queda en el log del servidor, nunca en la respuesta.

    Las HTTPException y los 422 los resuelve antes el ExceptionMiddleware de Starlette,
    así que aquí solo llega lo que ningún endpoint manejó.
    """
    logger.error("Error no manejado en %s %s", request.method, request.url.path, exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Error interno del servidor"},
    )


app.include_router(indicators.router)
app.include_router(enrichment.router)
app.include_router(correlation.router)
app.include_router(reports.router)


@app.get("/health", tags=["Health"], summary="Estado del servicio")
def health():
    return {"status": "ok"}
