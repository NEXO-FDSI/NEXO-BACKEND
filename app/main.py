import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.ai_component.vectorstore import ChromaVectorStore
from app.api import correlation, enrichment, indicators, investigations, reports
from app.enrichment.providers import PROVEEDORES
from app.correlation.attck_loader import load_attck_index
from app.core.config import settings

logging.basicConfig(
    level=settings.LOG_LEVEL, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
)
# En DEBUG imprimen las cabeceras, y ahí viajan las API keys. httpx lo usan las fuentes de
# enriquecimiento; httpx2 es el cliente interno del SDK de openai (3.x).
for _nombre in ("httpx", "httpx2"):
    logging.getLogger(_nombre).setLevel(max(logging.INFO, logging.getLogger().level))
logger = logging.getLogger(__name__)
http_logger = logging.getLogger("app.http")

DESCRIPCION = """
Enriquecimiento de indicadores de compromiso (IP, dominio, hash, URL) con correlación
trazable a MITRE ATT&CK e informes auditables para un analista SOC.

**Flujo** — cada paso requiere el anterior:

1. `POST /indicators` — ingesta, normalización y validación.
2. `POST /indicators/{id}/enrich` — reputación en OTX, ThreatFox y VirusTotal (con caché).
3. `POST /indicators/{id}/correlate` — resolución de entidad y, solo si hubo, técnicas ATT&CK.
4. `POST /indicators/{id}/report` — informe con análisis narrativo grounded (LLM + RAG).
5. `POST /reports/{id}/validate` — aceptación o rechazo por un analista.

Prototipo académico: sin autenticación por diseño (Seminario de Seguridad de la
Información 2026-2, Grupo 2, Escuela Colombiana de Ingeniería Julio Garavito).
"""

TAGS = [
    {"name": "Indicators", "description": "Ingesta de indicadores de compromiso."},
    {"name": "Enrichment", "description": "Reputación del indicador en OTX, ThreatFox y VirusTotal."},
    {"name": "Correlation", "description": "Cadena de dos etapas contra MITRE ATT&CK."},
    {"name": "Reports", "description": "Informe del indicador y validación humana."},
    {"name": "Investigations", "description": "Todas las investigaciones de la plataforma, paginadas."},
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
    allow_credentials=False,  # la API no usa cookies ni auth
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def medir_duracion(request: Request, call_next):
    """Una línea por request con su duración: la base para medir cada paso del pipeline."""
    inicio = time.perf_counter()
    response = await call_next(request)
    http_logger.info(
        "%s %s -> %d en %.0f ms", request.method, request.url.path, response.status_code,
        (time.perf_counter() - inicio) * 1000,
    )
    return response


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
app.include_router(investigations.router)


@app.get("/health", tags=["Health"], summary="Estado del servicio")
def health():
    return {"status": "ok"}


@app.get("/status", tags=["Health"], summary="Fuentes y proveedor de IA configurados")
def status_servicio():
    """Qué fuentes y qué IA usará el pipeline. Sin secretos y sin llamar a terceros: que
    una fuente esté configurada no garantiza que responda (eso lo dice su estado en /enrich)."""
    # Solo lo que muestra la interfaz: el respaldo sigue operando en llm_client, no se expone.
    return {
        "fuentes": [
            {"fuente": p.nombre, "etiqueta": p.etiqueta, "configurada": p.configurado}
            for p in PROVEEDORES
        ],
        "ia": {"proveedor": settings.LLM_PROVIDER, "modelo": settings.LLM_MODEL},
    }
