from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import (
    EnrichmentCache,
    Entity,
    EntityTechniqueLink,
    HumanValidation,
    Indicator,
    IndicatorEntityLink,
    Report,
)
from app.db.repositories.base import BaseRepository

indicator_repository = BaseRepository[Indicator](Indicator)


def get_by_valor(db: Session, valor: str) -> Indicator | None:
    """Por valor canónico (único en la tabla): resuelve el 409 de un indicador ya registrado."""
    return db.scalars(select(Indicator).where(Indicator.valor == valor).limit(1)).first()


def list_recientes(db: Session, limit: int) -> list[Indicator]:
    return list(db.scalars(select(Indicator).order_by(Indicator.id.desc()).limit(limit)))


def eliminar_en_cascada(db: Session, indicator: Indicator) -> dict[str, int]:
    """Borra el indicador y todo lo que cuelga de él. Devuelve cuántas filas por tabla.

    Las FK no tienen ON DELETE CASCADE: se borra en orden (hijos primero) dentro de la
    transacción del endpoint, sin migrar el esquema. Las entidades y sus links a técnicas
    son conocimiento compartido entre indicadores: solo se borran si quedan huérfanas. El
    catálogo `techniques` (ATT&CK) nunca se toca. Solo hace flush; el commit es del endpoint.
    """
    def borrar(stmt) -> int:
        return db.execute(stmt.execution_options(synchronize_session=False)).rowcount

    entidades = set(
        db.scalars(select(IndicatorEntityLink.entity_id).where(IndicatorEntityLink.indicator_id == indicator.id))
    )
    informes = select(Report.id).where(Report.indicator_id == indicator.id)
    eliminados = {
        "human_validation": borrar(delete(HumanValidation).where(HumanValidation.report_id.in_(informes))),
        "reports": borrar(delete(Report).where(Report.indicator_id == indicator.id)),
        "indicator_entity_link": borrar(
            delete(IndicatorEntityLink).where(IndicatorEntityLink.indicator_id == indicator.id)
        ),
        "enrichment_cache": borrar(delete(EnrichmentCache).where(EnrichmentCache.indicator_id == indicator.id)),
        "indicators": borrar(delete(Indicator).where(Indicator.id == indicator.id)),
    }

    # Entidades que ningún otro indicador referencia: se van con sus links a técnicas.
    usadas = set(
        db.scalars(
            select(IndicatorEntityLink.entity_id).where(IndicatorEntityLink.entity_id.in_(entidades)).distinct()
        )
    )
    huerfanas = entidades - usadas
    eliminados["entity_technique_link"] = borrar(
        delete(EntityTechniqueLink).where(EntityTechniqueLink.entity_id.in_(huerfanas))
    )
    eliminados["entities"] = borrar(delete(Entity).where(Entity.id.in_(huerfanas)))
    db.flush()
    return eliminados
