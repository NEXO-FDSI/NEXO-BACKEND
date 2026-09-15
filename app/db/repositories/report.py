from app.db.models import Report
from app.db.repositories.base import BaseRepository

report_repository = BaseRepository[Report](Report)
