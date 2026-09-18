from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.repositories import indicator_repository
from app.enrichment.client import ReputationAPIError
from app.enrichment.service import FUENTE, get_or_fetch_enrichment

router = APIRouter(tags=["enrichment"])


@router.post("/indicators/{indicator_id}/enrich")
def enrich_indicator(indicator_id: int, db: Session = Depends(get_db)):
    indicator = indicator_repository.get(db, indicator_id)
    if indicator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Indicador no encontrado"
        )

    try:
        resultado = get_or_fetch_enrichment(db, indicator)
        db.commit()
    except ReputationAPIError as exc:
        db.rollback()
        # 502 y nunca 200 'sin evidencia': no pude verificar != verifiqué y no hay nada.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"El servicio de reputación no respondió: {exc}",
        )

    return {"indicator_id": indicator_id, "fuente": FUENTE, **resultado}
