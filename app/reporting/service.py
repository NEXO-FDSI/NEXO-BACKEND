from sqlalchemy.orm import Session

from app.correlation.attck_loader import AttckIndex
from app.correlation.service import correlate_indicator
from app.db.models import Indicator, Report
from app.db.repositories import report_repository
from app.reporting.template import build_report_content, nivel_confianza


def generate_report(
    db: Session, indicator: Indicator, enrichment_detalle: dict, index: AttckIndex
) -> Report:
    """Correlaciona (idempotente), redacta con la plantilla y persiste. Sin commit."""
    resultado = correlate_indicator(db, indicator, enrichment_detalle, index)
    return report_repository.create(
        db,
        {
            "indicator_id": indicator.id,
            "contenido": build_report_content(indicator, enrichment_detalle, resultado),
            "nivel_confianza": nivel_confianza(resultado),
        },
    )
