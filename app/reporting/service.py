import json

from sqlalchemy.orm import Session

from app.ai_component.service import generate_grounded_analysis
from app.ai_component.vectorstore import VectorStore
from app.correlation.attck_loader import AttckIndex
from app.correlation.service import correlate_indicator
from app.db.models import Indicator, Report
from app.db.repositories import report_repository
from app.enrichment.service import get_or_fetch_enrichment
from app.reporting.severity import calcular_concordancia, calcular_severidad
from app.reporting.template import build_report_content, nivel_confianza


def generate_report(
    db: Session,
    indicator: Indicator,
    enrichment_detalle: dict,
    index: AttckIndex,
    vector_store: VectorStore,
) -> Report:
    """Correlaciona (idempotente), analiza, redacta con la plantilla y persiste. Sin commit."""
    resultado = correlate_indicator(db, indicator, enrichment_detalle, index)
    # Solo caché: el informe usa lo que /enrich ya obtuvo, nunca vuelve a salir a la red.
    fuentes = get_or_fetch_enrichment(db, indicator, consultar=False)["fuentes"]
    severidad = calcular_severidad(resultado, fuentes)
    concordancia = calcular_concordancia(resultado, fuentes, index)
    # Nunca propaga un fallo de IA: el registro dice por qué no hubo análisis.
    ia = generate_grounded_analysis(
        indicator, resultado, vector_store, fuentes=fuentes, concordancia=concordancia
    )
    metadatos = {
        "severidad": severidad,
        "concordancia": concordancia,
        "fuentes": [
            {k: f[k] for k in ("fuente", "etiqueta", "estado", "resumen", "error")} for f in fuentes
        ],
        "ia": ia,
    }
    return report_repository.create(
        db,
        {
            "indicator_id": indicator.id,
            "contenido": build_report_content(
                indicator, enrichment_detalle, resultado, ia,
                severidad=severidad, fuentes=fuentes, concordancia=concordancia,
            ),
            "nivel_confianza": nivel_confianza(resultado),
            "metadatos": json.dumps(metadatos, ensure_ascii=False),
        },
    )
