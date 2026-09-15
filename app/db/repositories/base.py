from typing import Generic, TypeVar

from sqlalchemy import inspect, select
from sqlalchemy.orm import Session

ModelType = TypeVar("ModelType")


class BaseRepository(Generic[ModelType]):
    """CRUD genérico. La Session siempre llega por parámetro, nunca se crea aquí."""

    def __init__(self, model: type[ModelType]):
        self.model = model
        self._pk = inspect(model).primary_key[0]

    def create(self, db: Session, obj_in: dict) -> ModelType:
        obj = self.model(**obj_in)
        db.add(obj)
        # flush y no commit: el límite transaccional lo decide quien inyecta la Session.
        db.flush()
        db.refresh(obj)
        return obj

    def get(self, db: Session, id) -> ModelType | None:
        return db.get(self.model, id)

    def list(self, db: Session, skip: int = 0, limit: int = 100) -> list[ModelType]:
        # order_by explícito: sin él, Postgres no garantiza orden con LIMIT.
        stmt = select(self.model).order_by(self._pk).offset(skip).limit(limit)
        return list(db.scalars(stmt))
