"""Orquestación del análisis grounded.

El LLM solo se invoca cuando hay contexto real que ofrecerle. Igual que la etapa (b) de
la correlación no corre si la (a) falló, aquí hay dos cortes explícitos antes de llamarlo.
Siempre devuelve un registro de trazabilidad: qué se envió, quién respondió, qué se
descartó, o por qué no hubo análisis.
"""

import logging

from app.ai_component.llm_client import LLMServiceError, generate_analysis
from app.ai_component.prompt_builder import construir_contexto, renderizar_prompt
from app.ai_component.schema import depurar, parsear
from app.ai_component.vectorstore import VectorStore
from app.db.models import Indicator

logger = logging.getLogger(__name__)


def generate_grounded_analysis(
    indicator: Indicator,
    correlation_result: dict,
    vector_store: VectorStore,
    fuentes: list[dict] = (),
    concordancia: list[dict] = (),
) -> dict:
    """Registro del análisis de IA (se persiste en reports.metadatos["ia"]).

    `estado`: "generado" | "no_llamado" | "fallido" | "descartado"; `analisis` es el
    AnalisisIA depurado (dict) o None; `motivo` explica por qué no lo hay.
    """
    ia = {
        "estado": "no_llamado", "motivo": None, "analisis": None, "descartes": [],
        "contexto": [], "prompt": None, "proveedor": None, "modelo": None,
        "latencia_ms": None, "tokens": None, "intentos_fallidos": [],
    }
    if not correlation_result["resuelto"]:
        # Corte 1: sin entidad resuelta no hay nada que explicar. Ni vector store ni LLM.
        ia["motivo"] = "sin entidad resuelta: por diseño no se consulta al modelo"
        return ia

    technique_texts = vector_store.get_by_ids([t["id"] for t in correlation_result["tecnicas"]])
    if not technique_texts:
        # Corte 2: sin texto recuperado no se llama al LLM con contexto vacío.
        ia["motivo"] = "sin texto oficial de ATT&CK recuperado para las técnicas de la entidad"
        return ia

    contexto = construir_contexto(indicator, correlation_result, technique_texts, fuentes, concordancia)
    prompt = renderizar_prompt(contexto)
    ia.update(contexto=contexto["bloques"], prompt=prompt)

    try:
        analisis, meta = generate_analysis(prompt, validar=parsear)
    except LLMServiceError as exc:
        # El informe se genera igual: el resto del contenido es determinístico. Pero el
        # motivo queda en el log y en los metadatos: sin esto, un 400 era invisible.
        logger.warning("análisis narrativo omitido para %s: %s", indicator.valor, exc)
        ia.update(estado="fallido", motivo=str(exc), intentos_fallidos=exc.intentos)
        return ia

    depurado, descartes = depurar(analisis, {b["id"] for b in contexto["bloques"]})
    ia.update(meta, descartes=descartes)
    if depurado is None:
        ia.update(estado="descartado", motivo="todo lo que redactó el modelo citaba fuera del contexto")
    else:
        ia.update(estado="generado", analisis=depurado.model_dump())
    return ia
