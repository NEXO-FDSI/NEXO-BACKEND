from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import EntityTechniqueLink
from app.db.repositories.base import BaseRepository

entity_technique_link_repository = BaseRepository[EntityTechniqueLink](EntityTechniqueLink)


def technique_ids_enlazadas(db: Session, entity_id: int, technique_ids: list[str]) -> set[str]:
    """De esas técnicas, las que ya tienen link con la entidad. Un solo SELECT."""
    stmt = select(EntityTechniqueLink.technique_id).where(
        EntityTechniqueLink.entity_id == entity_id,
        EntityTechniqueLink.technique_id.in_(technique_ids),
    )
    return set(db.scalars(stmt))
