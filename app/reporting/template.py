"""Plantilla fija del informe en Markdown. Se genera a partir de los datos estructurados
(que además se persisten en reports.metadatos); el Markdown es la vista descargable."""

from datetime import datetime, timezone

from app.db.models import Indicator
from app.enrichment.providers.base import describir

FUENTE_TECNICAS = 'MITRE ATT&CK STIX dataset — relationship "uses"'
ANALISIS_NO_DISPONIBLE = (
    "> Análisis narrativo no disponible. La información estructurada de\n"
    "> este informe (entidad, confianza, técnicas) es válida\n"
    "> independientemente de este apartado."
)
SEVERIDAD = {
    "critica": "Crítica", "alta": "Alta", "media": "Media", "baja": "Baja",
    "benigno": "Benigno conocido", "indeterminada": "Indeterminada",
}
TIPO_HALLAZGO = {"evidencia": "Evidencia", "inferencia": "Inferencia", "hipotesis": "Hipótesis"}
CONCORDANCIA = {
    "concuerda": "concuerda con la entidad asociada",
    "discrepa": "apunta a otra entidad",
    "sugiere": "sugiere una entidad que NEXO no resolvió",
    "no_comparable": "sin familias reconocibles en ATT&CK",
}


def nivel_confianza(correlation_result: dict) -> float:
    """Confianza de la asociación si hubo resolución; 0.0 si no."""
    return float(correlation_result["confianza"]) if correlation_result["resuelto"] else 0.0


def autoria_ia(meta: dict) -> str:
    """Línea de trazabilidad: qué proveedor y modelo redactó el análisis, y si fue respaldo."""
    linea = f"*Redactado por IA: {meta['proveedor']} · {meta['modelo']} · {meta['latencia_ms']} ms"
    if meta.get("intentos_fallidos"):
        caidos = ", ".join(i["proveedor"] for i in meta["intentos_fallidos"])
        linea += f" (respaldo: {caidos} no respondió)"
    return linea + ". Basado solo en el contexto citado: evidencia de las fuentes y texto oficial de ATT&CK.*"


def _celda(texto: str) -> str:
    return texto.replace("|", "/").replace("\n", " ")


def _seccion_fuentes(fuentes: list[dict], concordancia: list[dict]) -> list[str]:
    if not fuentes:
        return []
    lineas = ["", "### Fuentes consultadas", "", "| Fuente | Estado | Detalle |", "|---|---|---|"]
    for f in fuentes:
        detalle = describir(f["resumen"]) if f.get("resumen") else (f.get("error") or "—")
        lineas.append(f"| {f['etiqueta']} | {f['estado'].replace('_', ' ')} | {_celda(detalle)} |")
    for c in concordancia:
        entidades = f" ({', '.join(c['entidades'])})" if c["entidades"] else ""
        lineas.append(f"- **{c['etiqueta']}** {CONCORDANCIA[c['resultado']]}{entidades}.")
    return lineas


def _seccion_analisis(ia: dict | None) -> list[str]:
    analisis = (ia or {}).get("analisis")
    if not analisis:
        lineas = [ANALISIS_NO_DISPONIBLE]
        if ia and ia.get("motivo"):
            lineas.append(f">\n> Motivo: {ia['motivo']}.")
        return lineas

    lineas = [analisis["resumen"]] if analisis["resumen"] else []
    if analisis["hallazgos"]:
        lineas += ["", "**Hallazgos**", ""]
        for h in analisis["hallazgos"]:
            citas = f" — _{', '.join(h['fuentes'])}_" if h["fuentes"] else ""
            lineas.append(f"- **{TIPO_HALLAZGO[h['tipo']]}** · {h['afirmacion']}{citas}")
    if analisis["tecnicas_destacadas"]:
        lineas += ["", "**Técnicas destacadas**", ""]
        lineas += [f"- **{t['id']}** — {t['motivo']}" for t in analisis["tecnicas_destacadas"]]
    for clave, titulo in (
        ("investigacion_recomendada", "Investigación recomendada"),
        ("limitaciones", "Limitaciones"),
        ("informacion_faltante", "Información faltante"),
    ):
        if analisis[clave]:
            lineas += ["", f"**{titulo}**", "", *(f"- {item}" for item in analisis[clave])]
    lineas += ["", autoria_ia(ia)]
    if ia["descartes"]:
        lineas.append(
            f"*{len(ia['descartes'])} afirmación(es) del modelo descartada(s) por citar fuera del contexto.*"
        )
    return lineas


def build_report_content(
    indicator: Indicator,
    enrichment_detalle: dict,
    correlation_result: dict,
    ia: dict | None = None,
    *,
    severidad: dict | None = None,
    fuentes: list[dict] = (),
    concordancia: list[dict] = (),
) -> str:
    pulses = (enrichment_detalle.get("pulse_info") or {}).get("count") or 0
    lineas = [
        f"# Informe de indicador: {indicator.valor}",
        "",
        f"**Tipo:** {indicator.tipo}",
        f"**Fecha de generación:** {datetime.now(timezone.utc).isoformat()}",
        f"**Nivel de confianza:** {nivel_confianza(correlation_result)}",
    ]
    if severidad:
        lineas.append(f"**Severidad:** {SEVERIDAD[severidad['nivel']]} — {'; '.join(severidad['motivos'])}")
    lineas += [
        "",
        "## Enriquecimiento",
        "",
        "- Fuente: AlienVault OTX",
        f"- Evidencia encontrada: {'Sí' if pulses > 0 else 'No'}",
        f"- Reportes (pulses) que mencionan este indicador: {pulses}",
        *_seccion_fuentes(list(fuentes), list(concordancia)),
        "",
        "## Resolución de entidad y técnicas ATT&CK",
        "",
    ]

    if correlation_result["resuelto"]:
        entity = correlation_result["entity"]
        lineas += [
            f"- **Entidad asociada:** {entity['nombre']} ({entity['tipo']})",
            f"- **Evidencia de asociación:** {correlation_result['evidencia']}",
            f"- **Confianza de la asociación:** {correlation_result['confianza']}",
            "",
            "### Técnicas documentadas",
            "",
            "| ID | Técnica | Táctica |",
            "|---|---|---|",
            *(f"| {t['id']} | {t['nombre']} | {t['tactica']} |" for t in correlation_result["tecnicas"]),
            "",
            f"**Fuente de las técnicas:** {FUENTE_TECNICAS}",
        ]
    else:
        lineas += [
            "> **Sin evidencia suficiente para asociar este indicador a una entidad",
            "> conocida.** No se atribuye ninguna técnica ATT&CK — la ausencia de",
            "> asociación es un resultado válido, no un error del sistema.",
        ]

    # La sección existe siempre: si el análisis no está, se dice por qué en vez de
    # dejar un hueco que parezca un error de generación. Ya no hay sección "Estado de
    # validación": quedaba congelada al generarse; el estado vigente vive en la API.
    lineas += ["", "## Análisis", "", *_seccion_analisis(ia), ""]
    return "\n".join(lineas)
