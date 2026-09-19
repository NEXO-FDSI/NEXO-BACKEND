import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ai_component.vectorstore import VectorStore
from app.api.correlation import get_attck_index
from app.correlation.attck_loader import AttckIndex
from app.db.database import get_db
from app.db.repositories import indicator_repository
from app.db.repositories.enrichment_cache import get_by_indicator_and_source
from app.enrichment.service import FUENTE
from app.reporting.service import generate_report
from app.schemas.indicator import IndicatorCreate, IndicatorRead
from app.schemas.report import ReportRead

router = APIRouter(tags=["indicators"])


def get_vector_store(request: Request) -> VectorStore:
    """Store abierto una sola vez en el lifespan, igual que el índice ATT&CK."""
    return request.app.state.vector_store


@router.post("/indicators", status_code=status.HTTP_201_CREATED, response_model=IndicatorRead)
def create_indicator(payload: IndicatorCreate, db: Session = Depends(get_db)):
    """El formato ya lo validó IndicatorCreate (422). Aquí solo se persiste."""
    try:
        indicator = indicator_repository.create(db, payload.model_dump())
        # El commit es del endpoint: el repositorio solo hace flush a propósito.
        db.commit()
    except IntegrityError:
        # Sin rollback la sesión queda inutilizable (PendingRollbackError).
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="El indicador ya existe"
        )
    return IndicatorRead.model_validate(indicator)


@router.post(
    "/indicators/{indicator_id}/report",
    status_code=status.HTTP_201_CREATED,
    response_model=ReportRead,
)
def create_report(
    indicator_id: int,
    db: Session = Depends(get_db),
    index: AttckIndex = Depends(get_attck_index),
    vector_store: VectorStore = Depends(get_vector_store),
):
    indicator = indicator_repository.get(db, indicator_id)
    if indicator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Indicador no encontrado"
        )

    cacheado = get_by_indicator_and_source(db, indicator_id, FUENTE)
    if cacheado is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Debes ejecutar /enrich para este indicador antes de generar el informe",
        )

    report = generate_report(
        db, indicator, json.loads(cacheado.respuesta_json), index, vector_store
    )
    db.commit()
    return report
