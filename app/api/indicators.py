from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.repositories import indicator_repository
from app.schemas.indicator import IndicatorCreate, IndicatorRead

router = APIRouter(tags=["indicators"])


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
