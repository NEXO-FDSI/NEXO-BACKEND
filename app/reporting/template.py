"""Plantilla fija del informe en Markdown. Se genera a partir de los datos estructurados
(que además se persisten en reports.metadatos); el Markdown es la vista descargable."""

from datetime import datetime, timezone

from app.db.models import Indicator
from app.enrichment.providers.base import describir
from app.enrichment.service import FALLIDOS

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
CONFIANZA = {"alta": "Alta", "media": "Media", "baja": "Baja", "sin_evidencia": "Sin evidencia suficiente"}
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


def _seccion_fuentes(fuentes: list[dict], concordancia: list[dict], contradicciones: list[dict]) -> list[str]:
    if not fuentes:
        return []
    lineas = ["| Fuente | Estado | Detalle |", "|---|---|---|"]
    for f in fuentes:
        detalle = describir(f["resumen"]) if f.get("resumen") else (f.get("error") or "—")
        lineas.append(f"| {f['etiqueta']} | {f['estado'].replace('_', ' ')} | {_celda(detalle)} |")
    consultadas = [f["etiqueta"] for f in fuentes if f["estado"] in ("con_evidencia", "sin_evidencia")]
    fallidas = [f"{f['etiqueta']} ({f['estado'].replace('_', ' ')})" for f in fuentes if f["estado"] in FALLIDOS]
    lineas += ["", f"**Fuentes que respondieron:** {', '.join(consultadas) or 'ninguna'}"]
    if fallidas:
        lineas += [
            "",
            f"**Fuentes no disponibles:** {', '.join(fallidas)}. No se pudo verificar en ellas: "
            "su ausencia **no** significa \"sin evidencia\" y el resultado es parcial.",
        ]
    if concordancia:
        lineas.append("")
    for c in concordancia:
        entidades = f" ({', '.join(c['entidades'])})" if c["entidades"] else ""
        lineas.append(f"- **{c['etiqueta']}** {CONCORDANCIA[c['resultado']]}{entidades}.")
    lineas += ["", "### Contradicciones", ""]
    lineas += [f"- ⚠ {c['detalle']}." for c in contradicciones] or [
        "Ninguna detectada entre las fuentes que respondieron."
    ]
    return lineas


def _procedencia(tecnica: dict, etiqueta: dict[str, str]) -> str:
    """"vía entidad: OTX, ThreatFox; citada por OTX": de qué fuentes sale cada técnica."""
    def nombres(claves):
        return ", ".join(etiqueta.get(f, f) for f in claves)

    texto = f"vía entidad: {nombres(tecnica['fuentes'])}" if tecnica.get("fuentes") else "vía entidad"
    if tecnica.get("reportada_por"):
        texto += f"; citada por {nombres(tecnica['reportada_por'])}"
    return texto


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
    correlation_result: dict,
    ia: dict | None = None,
    *,
    severidad: dict | None = None,
    confianza: dict | None = None,
    fuentes: list[dict] = (),
    concordancia: list[dict] = (),
    contradicciones: list[dict] = (),
) -> str:
    fuentes = list(fuentes)
    etiqueta = {f["fuente"]: f["etiqueta"] for f in fuentes}
    cabecera = [
        f"**Tipo:** {indicator.tipo}",
        f"**Fecha de generación:** {datetime.now(timezone.utc).isoformat()}",
    ]
    if confianza:
        cabecera.append(f"**Nivel de confianza:** {CONFIANZA[confianza['nivel']]} — {'; '.join(confianza['motivos'])}")
    if severidad:
        cabecera.append(f"**Severidad:** {SEVERIDAD[severidad['nivel']]} — {'; '.join(severidad['motivos'])}")
    # "  \n" es un salto de línea duro en Markdown: con "\n" a secas, los cuatro campos se
    # renderizaban como un solo párrafo.
    lineas = [f"# Informe de indicador: {indicator.valor}", "", "  \n".join(cabecera)]
    con_evidencia = [f["etiqueta"] for f in fuentes if f["estado"] == "con_evidencia"]
    lineas += [
        "",
        "## Evidencia por fuente",
        "",
        f"- Evidencia encontrada: {'Sí, en ' + ', '.join(con_evidencia) if con_evidencia else 'No'}",
        "",
        *_seccion_fuentes(fuentes, list(concordancia), list(contradicciones)),
        "",
        "## Resolución de entidad y técnicas ATT&CK",
        "",
    ]

    if correlation_result["resuelto"]:
        entity = correlation_result["entity"]
        respaldo = ", ".join(etiqueta.get(f, f) for f in correlation_result.get("fuentes") or [])
        lineas += [
            f"- **Entidad asociada:** {entity['nombre']} ({entity['tipo']})",
            *([f"- **Respaldada por:** {respaldo}"] if respaldo else []),
            f"- **Evidencia de asociación:** {correlation_result['evidencia']}",
            f"- **Confianza de la asociación:** {correlation_result['confianza']}",
            "",
            "### Técnicas documentadas",
            "",
            "| ID | Técnica | Táctica | Procedencia |",
            "|---|---|---|---|",
            *(
                f"| {t['id']} | {t['nombre']} | {t['tactica']} | {_procedencia(t, etiqueta)} |"
                for t in correlation_result["tecnicas"]
            ),
            "",
            f"**Fuente de las técnicas:** {FUENTE_TECNICAS}, a partir de la entidad que "
            "respaldan las fuentes indicadas.",
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
