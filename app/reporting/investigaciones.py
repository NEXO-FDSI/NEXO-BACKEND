"""Investigaciones reconstruidas desde lo persistido, en lote y SIN escribir ni salir a la red.

Lo usan GET /indicators/{id} (una investigación, con la respuesta cruda de OTX completa) y
GET /investigations (páginas de hasta 10, con la respuesta de OTX recortada). Un solo
camino de construcción: una consulta por tabla para toda la página, no por indicador.
"""

import json
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.correlation.attck_loader import AttckIndex
from app.correlation.service import correlation_from_link
from app.db.models import EnrichmentCache, Entity, HumanValidation, Indicator, IndicatorEntityLink, Report
from app.enrichment.service import FUENTE, es_ip_no_publica, get_or_fetch_enrichment
from app.schemas.human_validation import HumanValidationRead
from app.schemas.indicator import IndicatorRead
from app.schemas.report import ReportRead

# Lo que la interfaz lee de OTX (app/domain/otx.ts del frontend). El resto de la respuesta
# cruda (cientos de KB por indicador) no viaja en los listados.
_CAMPOS_PULSE = ("id", "name", "created", "indicator_count", "tags", "malware_families")


def recortar_otx(crudo: dict) -> dict:
    info = crudo.get("pulse_info") or {}
    return {
        "type": crudo.get("type"),
        "validation": crudo.get("validation") or [],
        "pulse_info": {
            "count": info.get("count") or 0,
            "pulses": [
                {k: p.get(k) for k in _CAMPOS_PULSE} for p in info.get("pulses") or [] if isinstance(p, dict)
            ],
        },
    }


def construir(
    db: Session, indicators: list[Indicator], index: AttckIndex, *, detalle_completo: bool
) -> list[dict]:
    """Snapshot de cada indicador (mismo orden): indicator, enrichment, correlation, reports,
    validations. Cinco consultas en total, sin importar cuántos indicadores sean."""
    ids = [i.id for i in indicators]

    cache: dict[int, dict[str, dict]] = defaultdict(dict)
    for fila in db.scalars(
        select(EnrichmentCache).where(EnrichmentCache.indicator_id.in_(ids)).order_by(EnrichmentCache.id)
    ):
        cache[fila.indicator_id][fila.fuente_api] = json.loads(fila.respuesta_json)  # gana la más reciente

    links: dict[int, IndicatorEntityLink] = {}
    for link in db.scalars(
        select(IndicatorEntityLink)
        .where(IndicatorEntityLink.indicator_id.in_(ids))
        .order_by(IndicatorEntityLink.id)
    ):
        links[link.indicator_id] = link  # gana el más reciente, como get_by_indicator
    # Precarga las entidades de esos links en una consulta: luego link.entity sale del identity
    # map de la sesión en vez de lanzar una consulta por link. La referencia se guarda a
    # propósito: el identity map es débil y, si el resultado se descartara, los objetos se
    # liberarían y cada link.entity volvería a consultar (lo detectó el test de consultas).
    entidades = (
        list(db.scalars(select(Entity).where(Entity.id.in_({link.entity_id for link in links.values()}))))
        if links
        else []
    )

    informes: dict[int, list[Report]] = defaultdict(list)
    for informe in db.scalars(select(Report).where(Report.indicator_id.in_(ids)).order_by(Report.id)):
        informes[informe.indicator_id].append(informe)

    indicador_de = {r.id: r.indicator_id for lista in informes.values() for r in lista}
    validaciones: dict[int, list[HumanValidation]] = defaultdict(list)
    if indicador_de:
        for v in db.scalars(
            select(HumanValidation).where(HumanValidation.report_id.in_(indicador_de)).order_by(HumanValidation.id)
        ):
            validaciones[indicador_de[v.report_id]].append(v)

    snapshots = []
    for ind in indicators:
        crudos = cache.get(ind.id, {})
        # Igual que detalle_otx: {} si la IP no se consulta a terceros; None si falta /enrich.
        detalle = {} if es_ip_no_publica(ind) else crudos.get(FUENTE)
        enrichment = correlation = None
        if detalle is not None:
            resultado = get_or_fetch_enrichment(db, ind, consultar=False, cache=crudos)
            if not detalle_completo:
                resultado["detalle"] = recortar_otx(resultado["detalle"])
            enrichment = {"indicator_id": ind.id, "fuente": FUENTE, **resultado, "detalle_completo": detalle_completo}
            snapshot = correlation_from_link(links.get(ind.id), detalle, index)
            correlation = {"indicator_id": ind.id, **snapshot} if snapshot else None
        snapshots.append({
            "indicator": IndicatorRead.model_validate(ind),
            "enrichment": enrichment,
            "correlation": correlation,
            "reports": [ReportRead.model_validate(r) for r in informes.get(ind.id, [])],
            "validations": [HumanValidationRead.model_validate(v) for v in validaciones.get(ind.id, [])],
        })
    del entidades  # vivas hasta aquí: todos los link.entity ya se resolvieron
    return snapshots
