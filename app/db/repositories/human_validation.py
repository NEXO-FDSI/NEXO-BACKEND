from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import HumanValidation
from app.db.repositories.base import BaseRepository

human_validation_repository = BaseRepository[HumanValidation](HumanValidation)


def list_by_reports(db: Session, report_ids: list[int]) -> list[HumanValidation]:
    """Historial de decisiones de esos informes, en orden cronológico."""
    stmt = (
        select(HumanValidation)
        .where(HumanValidation.report_id.in_(report_ids))
        .order_by(HumanValidation.id)
    )
    return list(db.scalars(stmt))
