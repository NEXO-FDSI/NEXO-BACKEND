from app.db.models import Technique
from app.db.repositories.base import BaseRepository

technique_repository = BaseRepository[Technique](Technique)
