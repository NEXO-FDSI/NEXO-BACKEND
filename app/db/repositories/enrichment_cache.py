from app.db.models import EnrichmentCache
from app.db.repositories.base import BaseRepository

enrichment_cache_repository = BaseRepository[EnrichmentCache](EnrichmentCache)
