from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Indicator
from app.db.repositories.base import BaseRepository

indicator_repository = BaseRepository[Indicator](Indicator)


def get_by_valor(db: Session, valor: str) -> Indicator | None:
    """Por valor canónico (único en la tabla): resuelve el 409 de un indicador ya registrado."""
    return db.scalars(select(Indicator).where(Indicator.valor == valor).limit(1)).first()


def list_recientes(db: Session, limit: int) -> list[Indicator]:
    return list(db.scalars(select(Indicator).order_by(Indicator.id.desc()).limit(limit)))
