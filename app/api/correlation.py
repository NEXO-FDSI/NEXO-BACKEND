import json

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.correlation.attck_loader import AttckIndex
from app.correlation.service import correlate_indicator
from app.db.database import get_db
from app.db.repositories import indicator_repository
from app.db.repositories.enrichment_cache import get_by_indicator_and_source
from app.enrichment.service import FUENTE

router = APIRouter(tags=["correlation"])


def get_attck_index(request: Request) -> AttckIndex:
    """Índice cargado una sola vez en el lifespan, nunca por request."""
    return request.app.state.attck_index


@router.post("/indicators/{indicator_id}/correlate")
def correlate(
    indicator_id: int,
    db: Session = Depends(get_db),
    index: AttckIndex = Depends(get_attck_index),
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
            detail="Debes ejecutar /enrich para este indicador antes de correlacionar",
        )

    resultado = correlate_indicator(db, indicator, json.loads(cacheado.respuesta_json), index)
    db.commit()
    return {"indicator_id": indicator_id, **resultado}
