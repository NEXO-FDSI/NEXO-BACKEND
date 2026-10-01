from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Report
from app.db.repositories.base import BaseRepository

report_repository = BaseRepository[Report](Report)


def list_by_indicator(db: Session, indicator_id: int) -> list[Report]:
    """Todas las versiones del informe, de la más antigua a la más reciente."""
    stmt = select(Report).where(Report.indicator_id == indicator_id).order_by(Report.id)
    return list(db.scalars(stmt))
