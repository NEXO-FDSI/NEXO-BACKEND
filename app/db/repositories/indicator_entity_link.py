from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import IndicatorEntityLink
from app.db.repositories.base import BaseRepository

indicator_entity_link_repository = BaseRepository[IndicatorEntityLink](IndicatorEntityLink)


def get_by_indicator_and_entity(
    db: Session, indicator_id: int, entity_id: int
) -> IndicatorEntityLink | None:
    stmt = (
        select(IndicatorEntityLink)
        .where(
            IndicatorEntityLink.indicator_id == indicator_id,
            IndicatorEntityLink.entity_id == entity_id,
        )
        .limit(1)
    )
    return db.scalars(stmt).first()


def get_by_indicator(db: Session, indicator_id: int) -> IndicatorEntityLink | None:
    """Último link de la etapa (a) para ese indicador, si /correlate resolvió alguna vez."""
    stmt = (
        select(IndicatorEntityLink)
        .where(IndicatorEntityLink.indicator_id == indicator_id)
        .order_by(IndicatorEntityLink.id.desc())
        .limit(1)
    )
    return db.scalars(stmt).first()
