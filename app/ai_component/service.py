"""Orquestación del análisis grounded.

El LLM solo se invoca cuando hay contexto real que ofrecerle. Igual que la etapa (b) de
la correlación no corre si la (a) falló, aquí hay dos cortes explícitos antes de llamarlo.
"""

import logging

from app.ai_component.llm_client import LLMServiceError, generate_analysis
from app.ai_component.prompt_builder import build_analysis_prompt
from app.ai_component.vectorstore import VectorStore
from app.db.models import Indicator

logger = logging.getLogger(__name__)


def generate_grounded_analysis(
    indicator: Indicator, correlation_result: dict, vector_store: VectorStore
) -> tuple[str | None, dict | None]:
    """(párrafo, meta de la llamada), o (None, None) si no hay nada grounded que redactar
    o la IA falló. `meta` dice qué proveedor y modelo redactó y cuánto tardó.

    Recibe el indicador porque el prompt lo necesita: el spec de la etapa fija ambas
    firmas y correlation_result no lo incluye.
    """
    if not correlation_result["resuelto"]:
        # Corte 1: sin entidad resuelta no hay nada que explicar. Ni vector store ni LLM.
        return None, None

    technique_texts = vector_store.get_by_ids(
        [t["id"] for t in correlation_result["tecnicas"]]
    )
    if not technique_texts:
        # Corte 2: sin texto recuperado no se llama al LLM con contexto vacío.
        return None, None

    try:
        return generate_analysis(
            build_analysis_prompt(indicator, correlation_result, technique_texts)
        )
    except LLMServiceError as exc:
        # El informe se genera igual: el resto del contenido es determinístico. Pero el
        # motivo queda en el log: sin esto, un 400 del proveedor era invisible.
        logger.warning("análisis narrativo omitido para %s: %s", indicator.valor, exc)
        return None, None
