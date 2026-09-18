"""Enriquecimiento con caché. Orquesta cliente + persistencia, sin depender de FastAPI."""

import json

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Indicator
from app.db.repositories.enrichment_cache import (
    enrichment_cache_repository,
    get_by_indicator_and_source,
)
from app.enrichment import client  # el módulo, no el símbolo: así el patch de los tests aplica

FUENTE = "alienvault_otx"


def get_or_fetch_enrichment(db: Session, indicator: Indicator) -> dict:
    """Reputación del indicador, de caché si existe. Deja propagar ReputationAPIError."""
    cacheado = get_by_indicator_and_source(db, indicator.id, FUENTE)

    if cacheado is not None:
        crudo = json.loads(cacheado.respuesta_json)  # cero HTTP
    else:
        crudo = client.fetch_reputation(
            indicator.tipo, indicator.valor, settings.REPUTATION_API_KEY
        )
        enrichment_cache_repository.create(
            db,
            {
                "indicator_id": indicator.id,
                "fuente_api": FUENTE,
                "respuesta_json": json.dumps(crudo),
            },
        )

    # .get() encadenado: un cambio de formato en OTX da 'sin evidencia', no un KeyError.
    pulsos = crudo.get("pulse_info", {}).get("count", 0)
    return {"tiene_evidencia": pulsos > 0, "detalle": crudo}
