from app.db.models import Entity
from app.db.repositories.base import BaseRepository

entity_repository = BaseRepository[Entity](Entity)
