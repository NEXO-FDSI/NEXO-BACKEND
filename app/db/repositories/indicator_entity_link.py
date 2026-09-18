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
