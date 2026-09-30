from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Technique
from app.db.repositories.base import BaseRepository

technique_repository = BaseRepository[Technique](Technique)


def ids_existentes(db: Session, technique_ids: list[str]) -> set[str]:
    """De esos ids, los que ya están en la tabla techniques. Un solo SELECT."""
    return set(db.scalars(select(Technique.id).where(Technique.id.in_(technique_ids))))
