from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.ai_component.vectorstore import ChromaVectorStore
from app.api import correlation, enrichment, indicators, reports
from app.correlation.attck_loader import load_attck_index
from app.core.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # El bundle STIX se parsea una sola vez por proceso, nunca por request.
    app.state.attck_index = load_attck_index(settings.ATTCK_STIX_PATH)
    app.state.vector_store = ChromaVectorStore()
    yield


app = FastAPI(title="NEXO Intel API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(indicators.router)
app.include_router(enrichment.router)
app.include_router(correlation.router)
app.include_router(reports.router)


@app.get("/health")
def health():
    return {"status": "ok"}
