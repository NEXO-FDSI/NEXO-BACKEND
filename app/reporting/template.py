"""Plantilla fija del informe. La Etapa 8 agrega la sección de análisis narrativo."""

from datetime import datetime, timezone

from app.db.models import Indicator

FUENTE_TECNICAS = 'MITRE ATT&CK STIX dataset — relationship "uses"'
ANALISIS_NO_DISPONIBLE = (
    "> Análisis narrativo no disponible. La información estructurada de\n"
    "> este informe (entidad, confianza, técnicas) es válida\n"
    "> independientemente de este apartado."
)


def nivel_confianza(correlation_result: dict) -> float:
    """Confianza de la asociación si hubo resolución; 0.0 si no."""
    return float(correlation_result["confianza"]) if correlation_result["resuelto"] else 0.0


def build_report_content(
    indicator: Indicator,
    enrichment_detalle: dict,
    correlation_result: dict,
    analysis_text: str | None = None,
) -> str:
    pulses = (enrichment_detalle.get("pulse_info") or {}).get("count") or 0
    lineas = [
        f"# Informe de indicador: {indicator.valor}",
        "",
        f"**Tipo:** {indicator.tipo}",
        f"**Fecha de generación:** {datetime.now(timezone.utc).isoformat()}",
        f"**Nivel de confianza:** {nivel_confianza(correlation_result)}",
        "",
        "## Enriquecimiento",
        "",
        "- Fuente: AlienVault OTX",
        f"- Evidencia encontrada: {'Sí' if pulses > 0 else 'No'}",
        f"- Reportes (pulses) que mencionan este indicador: {pulses}",
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
    # dejar un hueco que parezca un error de generación.
    lineas += ["", "## Análisis", "", analysis_text or ANALISIS_NO_DISPONIBLE]
    lineas += ["", "## Estado de validación", "", "Pendiente de revisión humana.", ""]
    return "\n".join(lineas)
