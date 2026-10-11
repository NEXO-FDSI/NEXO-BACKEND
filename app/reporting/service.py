import json

from sqlalchemy.orm import Session

from app.ai_component.service import generate_grounded_analysis
from app.ai_component.vectorstore import VectorStore
from app.correlation.attck_loader import AttckIndex
from app.correlation.service import correlate_indicator
from app.db.models import Indicator, Report
from app.db.repositories import report_repository
from app.enrichment.service import cobertura, get_or_fetch_enrichment
from app.reporting.severity import evaluar
from app.reporting.template import build_report_content, nivel_confianza


def generate_report(
    db: Session,
    indicator: Indicator,
    crudos: dict[str, dict],
    index: AttckIndex,
    vector_store: VectorStore,
) -> Report:
    """Correlaciona (idempotente), analiza, redacta con la plantilla y persiste. Sin commit.

    crudos: respuestas cacheadas por fuente (`crudos_enriquecidos`). Solo caché: el informe
    usa lo que /enrich ya obtuvo, nunca vuelve a salir a la red.
    """
    enriquecimiento = get_or_fetch_enrichment(db, indicator, consultar=False, cache=crudos)
    fuentes = enriquecimiento["fuentes"]
    resultado = correlate_indicator(db, indicator, enriquecimiento["detalle"], index, fuentes)
    evaluacion = evaluar(resultado, fuentes, index)
    severidad, confianza = evaluacion["severidad"], evaluacion["confianza"]
    concordancia, contradicciones = evaluacion["concordancia"], evaluacion["contradicciones"]
    # Nunca propaga un fallo de IA: el registro dice por qué no hubo análisis.
    ia = generate_grounded_analysis(
        indicator, resultado, vector_store, fuentes=fuentes, contradicciones=contradicciones
    )
    metadatos = {
        "severidad": severidad,
        "confianza": confianza,
        "cobertura": cobertura(fuentes),
        "contradicciones": contradicciones,
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
                indicator, resultado, ia,
                severidad=severidad, confianza=confianza, fuentes=fuentes,
                concordancia=concordancia, contradicciones=contradicciones,
            ),
            "nivel_confianza": nivel_confianza(resultado),
            "metadatos": json.dumps(metadatos, ensure_ascii=False),
        },
    )
