"""Orquestación del análisis grounded.

El LLM solo se invoca cuando hay contexto real que ofrecerle. Igual que la etapa (b) de
la correlación no corre si la (a) falló, aquí hay dos cortes explícitos antes de llamarlo.
Siempre devuelve un registro de trazabilidad: qué se envió, quién respondió, qué se
descartó, o por qué no hubo análisis.
"""

import logging
import math

from app.ai_component.llm_client import LLMServiceError, embed_text, generate_analysis
from app.ai_component.prompt_builder import (
    REGLAS,
    REGLAS_LOTE,
    construir_contexto,
    construir_contexto_lote,
    renderizar_prompt,
    tecnicas_candidatas_lote,
)
from app.ai_component.schema import depurar, parsear
from app.ai_component.vectorstore import VectorStore
from app.db.models import Indicator
from app.enrichment.providers.base import unicos

logger = logging.getLogger(__name__)

# El endpoint de embeddings es local (Ollama): si no responde rápido, se sigue sin él.
TIMEOUT_EMBEDDING = 10.0
_TIPO = {"ip": "IP address", "domain": "domain name", "url": "URL", "hash": "file hash"}


def consulta_semantica(indicator: Indicator, correlation_result: dict, fuentes: list[dict]) -> str:
    """Lo que se sabe del indicador, en inglés como el texto de ATT&CK: tipo, entidad y las
    familias y etiquetas (ya saneadas) de las fuentes que lo encontraron."""
    etiquetas = unicos(
        (x for f in fuentes if f["estado"] == "con_evidencia" and f.get("resumen")
         for x in f["resumen"]["familias"] + f["resumen"]["etiquetas"]),
        maximo=20,
    )
    texto = f"Indicator of compromise: {_TIPO.get(indicator.tipo, indicator.tipo)} linked to {correlation_result['entity']['nombre']}."
    return texto + (f" Threat labels reported by intelligence sources: {', '.join(etiquetas)}." if etiquetas else "")


def _coseno(a: list[float], b: list[float]) -> float:
    normas = math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b))
    return sum(x * y for x, y in zip(a, b)) / normas if normas else 0.0


def ordenar_por_afinidad(consulta: str, technique_texts: dict[str, dict]) -> dict:
    """{metodo, consulta, motivo, puntajes}: similitud coseno entre la consulta y cada técnica.

    Nunca tumba el informe: sin embedding de la consulta (Ollama caído, timeout) o sin
    embeddings sembrados, `metodo` = "por_tactica" y `motivo` dice por qué.
    """
    seleccion = {"metodo": "por_tactica", "consulta": consulta, "motivo": None, "puntajes": {}}
    vectores = {tid: t["embedding"] for tid, t in technique_texts.items() if t.get("embedding")}
    if not vectores:
        seleccion["motivo"] = "las técnicas no tienen embeddings sembrados"
        return seleccion
    try:
        consulta_vec = embed_text(consulta, timeout=TIMEOUT_EMBEDDING)
    except Exception as exc:  # cualquier fallo del endpoint: la selección por táctica sigue siendo válida
        logger.warning("sin embedding de la consulta; selección por táctica: %s", exc)
        seleccion["motivo"] = f"no se obtuvo el embedding de la consulta: {exc}"
        return seleccion
    puntajes = {tid: round(_coseno(consulta_vec, v), 4) for tid, v in vectores.items()}
    seleccion.update(metodo="semantica", puntajes=dict(sorted(puntajes.items(), key=lambda kv: -kv[1])))
    return seleccion


def _registro() -> dict:
    return {
        "estado": "no_llamado", "motivo": None, "analisis": None, "descartes": [],
        "contexto": [], "prompt": None, "proveedor": None, "modelo": None,
        "latencia_ms": None, "tokens": None, "intentos_fallidos": [], "seleccion": None,
    }


def _redactar(ia: dict, contexto: dict, reglas: str, sobre: str) -> dict:
    """Llama al LLM con el contexto, valida su JSON y descarta lo que cite fuera del contexto.
    Nunca propaga un fallo de IA: el registro dice qué pasó."""
    prompt = renderizar_prompt(contexto, reglas)
    ia.update(contexto=contexto["bloques"], prompt=prompt)

    try:
        analisis, meta = generate_analysis(prompt, validar=parsear)
    except LLMServiceError as exc:
        # El informe se genera igual: el resto del contenido es determinístico. Pero el
        # motivo queda en el log y en los metadatos: sin esto, un 400 era invisible.
        logger.warning("análisis narrativo omitido para %s: %s", sobre, exc)
        ia.update(estado="fallido", motivo=str(exc), intentos_fallidos=exc.intentos)
        return ia

    depurado, descartes = depurar(analisis, {b["id"] for b in contexto["bloques"]})
    ia.update(meta, descartes=descartes)
    if depurado is None:
        ia.update(estado="descartado", motivo="todo lo que redactó el modelo citaba fuera del contexto")
    else:
        ia.update(estado="generado", analisis=depurado.model_dump())
    return ia


def generate_grounded_analysis(
    indicator: Indicator,
    correlation_result: dict,
    vector_store: VectorStore,
    fuentes: list[dict] = (),
    contradicciones: list[dict] = (),
) -> dict:
    """Registro del análisis de IA (se persiste en reports.metadatos["ia"]).

    `estado`: "generado" | "no_llamado" | "fallido" | "descartado"; `analisis` es el
    AnalisisIA depurado (dict) o None; `motivo` explica por qué no lo hay.
    """
    ia = _registro()
    if not correlation_result["resuelto"]:
        # Corte 1: sin entidad resuelta no hay nada que explicar. Ni vector store ni LLM.
        ia["motivo"] = "sin entidad resuelta: por diseño no se consulta al modelo"
        return ia

    technique_texts = vector_store.get_by_ids([t["id"] for t in correlation_result["tecnicas"]])
    if not technique_texts:
        # Corte 2: sin texto recuperado no se llama al LLM con contexto vacío.
        ia["motivo"] = "sin texto oficial de ATT&CK recuperado para las técnicas de la entidad"
        return ia

    # Las técnicas que ve el modelo son las de la entidad más afines a la evidencia del
    # indicador (embeddings), no solo un reparto por táctica.
    seleccion = ordenar_por_afinidad(consulta_semantica(indicator, correlation_result, list(fuentes)), technique_texts)
    ia["seleccion"] = seleccion
    contexto = construir_contexto(
        indicator, correlation_result, technique_texts, fuentes, contradicciones, puntajes=seleccion["puntajes"]
    )
    return _redactar(ia, contexto, REGLAS, indicator.valor)


def generate_batch_analysis(correlacion: dict, vector_store: VectorStore, sobre: str = "lote") -> dict:
    """Registro del análisis de IA de un lote (Fase 7c), con los mismos cortes que el de un
    indicador. El modelo solo redacta: la agrupación y la conclusión ya las decidió NEXO."""
    ia = _registro()
    if not any(i["estado"] == "participa" for i in correlacion["indicadores"]):
        # Corte 1: ningún indicador resolvió entidad. Ni vector store ni LLM.
        ia["motivo"] = "ningún indicador del lote resolvió entidad: por diseño no se consulta al modelo"
        return ia

    technique_texts = vector_store.get_by_ids([t["id"] for t in tecnicas_candidatas_lote(correlacion)])
    if not technique_texts:
        # Corte 2: igual que en el informe individual, sin texto oficial no se llama al LLM.
        ia["motivo"] = "sin texto oficial de ATT&CK recuperado para las técnicas del lote"
        return ia

    # Sin embeddings: primero las técnicas que documentan varias entidades, luego por táctica.
    ia["seleccion"] = {"metodo": "solapamiento_y_tactica", "consulta": None, "motivo": None, "puntajes": {}}
    return _redactar(ia, construir_contexto_lote(correlacion, technique_texts), REGLAS_LOTE, sobre)
