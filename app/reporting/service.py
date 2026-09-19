from sqlalchemy.orm import Session

from app.ai_component.service import generate_grounded_analysis
from app.ai_component.vectorstore import VectorStore
from app.correlation.attck_loader import AttckIndex
from app.correlation.service import correlate_indicator
from app.db.models import Indicator, Report
from app.db.repositories import report_repository
from app.reporting.template import build_report_content, nivel_confianza


def generate_report(
    db: Session,
    indicator: Indicator,
    enrichment_detalle: dict,
    index: AttckIndex,
    vector_store: VectorStore,
) -> Report:
    """Correlaciona (idempotente), redacta con la plantilla y persiste. Sin commit."""
    resultado = correlate_indicator(db, indicator, enrichment_detalle, index)
    # Nunca propaga un fallo de IA: devuelve None y el informe sale sin narrativa.
    analisis = generate_grounded_analysis(indicator, resultado, vector_store)
    return report_repository.create(
        db,
        {
            "indicator_id": indicator.id,
            "contenido": build_report_content(
                indicator, enrichment_detalle, resultado, analisis
            ),
            "nivel_confianza": nivel_confianza(resultado),
        },
    )
