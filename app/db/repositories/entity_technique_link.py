from app.db.models import EntityTechniqueLink
from app.db.repositories.base import BaseRepository

entity_technique_link_repository = BaseRepository[EntityTechniqueLink](EntityTechniqueLink)
