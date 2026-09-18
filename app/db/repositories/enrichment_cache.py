from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import EnrichmentCache
from app.db.repositories.base import BaseRepository

enrichment_cache_repository = BaseRepository[EnrichmentCache](EnrichmentCache)


def get_by_indicator_and_source(
    db: Session, indicator_id: int, fuente_api: str
) -> EnrichmentCache | None:
    """Última entrada cacheada de esa fuente para ese indicador, si existe."""
    # ponytail: order_by(id.desc()) porque el esquema no tiene constraint único sobre
    # (indicator_id, fuente_api); dos enriquecimientos concurrentes podrían insertar dos
    # filas. Si eso pasa en la práctica, la salida es una migración con UniqueConstraint.
    stmt = (
        select(EnrichmentCache)
        .where(
            EnrichmentCache.indicator_id == indicator_id,
            EnrichmentCache.fuente_api == fuente_api,
        )
        .order_by(EnrichmentCache.id.desc())
        .limit(1)
    )
    return db.scalars(stmt).first()
