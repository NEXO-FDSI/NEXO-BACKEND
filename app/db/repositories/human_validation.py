from app.db.models import HumanValidation
from app.db.repositories.base import BaseRepository

human_validation_repository = BaseRepository[HumanValidation](HumanValidation)
