from app.db.models import Indicator
from app.db.repositories.base import BaseRepository

indicator_repository = BaseRepository[Indicator](Indicator)
