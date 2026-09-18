from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import EntityTechniqueLink
from app.db.repositories.base import BaseRepository

entity_technique_link_repository = BaseRepository[EntityTechniqueLink](EntityTechniqueLink)


def get_by_entity_and_technique(
    db: Session, entity_id: int, technique_id: str
) -> EntityTechniqueLink | None:
    stmt = (
        select(EntityTechniqueLink)
        .where(
            EntityTechniqueLink.entity_id == entity_id,
            EntityTechniqueLink.technique_id == technique_id,
        )
        .limit(1)
    )
    return db.scalars(stmt).first()
