from app.db.models import IndicatorEntityLink
from app.db.repositories.base import BaseRepository

indicator_entity_link_repository = BaseRepository[IndicatorEntityLink](IndicatorEntityLink)
