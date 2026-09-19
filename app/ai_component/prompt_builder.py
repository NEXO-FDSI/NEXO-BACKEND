"""Construcción del prompt grounded. El LLM no decide nada: solo redacta sobre este texto."""

from app.db.models import Indicator

# Tope de contexto: una entidad puede traer hasta 130 técnicas (kimsuky) con descripciones
# de ~1300 chars de mediana. Sin recorte el prompt desborda el num_ctx de Ollama, que
# trunca por el principio y se come justo las reglas de abajo. La tabla determinística del
# informe sigue listando TODAS las técnicas: el recorte solo afecta al párrafo narrativo.
MAX_TECNICAS = 8
MAX_CHARS_DESC = 600

CABECERA = """Eres un asistente que redacta la sección de análisis de un informe de
inteligencia de amenazas para un analista de seguridad.

Reglas estrictas:
- Usa EXCLUSIVAMENTE la información provista abajo. No agregues
  técnicas, tácticas ni afirmaciones que no estén en este contexto.
- Redacta un párrafo breve (3-5 frases) explicando, en términos que un
  analista entienda rápido, por qué este indicador se asocia a esta
  entidad y qué implican las técnicas listadas.
- Si algo no está en el contexto provisto, no lo menciones."""


def _cuerpo(document: str) -> str:
    """Descripción oficial de la técnica, recortada y sin repetir el encabezado.

    El documento sembrado empieza con "{nombre} ({tactica})\\n\\n", línea que ya va en el
    encabezado ### del bloque.
    """
    descripcion = document.split("\n\n", 1)[-1].strip()
    if len(descripcion) <= MAX_CHARS_DESC:
        return descripcion
    return descripcion[:MAX_CHARS_DESC].rstrip() + "…"


def build_analysis_prompt(
    indicator: Indicator, correlation_result: dict, technique_texts: dict[str, dict]
) -> str:
    entity = correlation_result["entity"]
    # Se respeta el orden de la Etapa 6 y se omiten las técnicas que no estén en el índice.
    tecnicas = [t["id"] for t in correlation_result["tecnicas"] if t["id"] in technique_texts]
    mostradas = tecnicas[:MAX_TECNICAS]

    lineas = [
        CABECERA,
        "",
        f"Indicador: {indicator.tipo} — {indicator.valor}",
        f"Entidad asociada: {entity['nombre']} ({entity['tipo']})",
        f"Evidencia de asociación: {correlation_result['evidencia']}",
        f"Confianza de la asociación: {correlation_result['confianza']}",
        "",
        "Técnicas documentadas (texto oficial de MITRE ATT&CK):",
    ]
    if len(mostradas) < len(correlation_result["tecnicas"]):
        lineas.append(
            f"(se muestran {len(mostradas)} de {len(correlation_result['tecnicas'])} "
            "técnicas asociadas)"
        )

    for technique_id in mostradas:
        datos = technique_texts[technique_id]
        meta = datos.get("metadata") or {}
        lineas += [
            "",
            f"### {technique_id} — {meta.get('nombre', '')} ({meta.get('tactica', '')})",
            _cuerpo(datos["document"]),
        ]

    lineas += ["", "Redacta el párrafo de análisis ahora."]
    return "\n".join(lineas)
