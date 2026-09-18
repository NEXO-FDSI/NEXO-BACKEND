from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Entity
from app.db.repositories.base import BaseRepository

entity_repository = BaseRepository[Entity](Entity)


def get_by_nombre(db: Session, nombre: str) -> Entity | None:
    return db.scalars(select(Entity).where(Entity.nombre == nombre).limit(1)).first()
