from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.repositories import human_validation_repository, report_repository
from app.schemas.human_validation import HumanValidationRead, HumanValidationRequest

router = APIRouter(tags=["reports"])


@router.post(
    "/reports/{report_id}/validate",
    status_code=status.HTTP_201_CREATED,
    response_model=HumanValidationRead,
)
def validate_report(
    report_id: int, payload: HumanValidationRequest, db: Session = Depends(get_db)
):
    if report_repository.get(db, report_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Informe no encontrado"
        )
    # Cada validación es una fila nueva: el historial completo queda auditable.
    validation = human_validation_repository.create(
        db, {"report_id": report_id, **payload.model_dump()}
    )
    db.commit()
    return validation
