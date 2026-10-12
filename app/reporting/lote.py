"""Informe conjunto de un lote (Fase 7c): plantilla fija en Markdown sobre la correlación
determinística del lote, más el análisis del LLM. Sin FastAPI.

Los valores de los indicadores van siempre como `código`: así remark-gfm no los convierte en
enlaces clicables a infraestructura maliciosa.
"""

import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.ai_component.service import generate_batch_analysis
from app.ai_component.vectorstore import VectorStore
from app.correlation.attck_loader import AttckIndex
from app.correlation.lote import SIN_RELACION, correlacionar_lote
from app.db.models import Batch, BatchReport
from app.reporting.template import CONFIANZA, SEVERIDAD, _seccion_analisis

SENAL = {"pulse_compartido": "Pulse compartido", "infraestructura": "Infraestructura", "misma_entidad": "Misma entidad"}
ORIGEN = {"alienvault_otx": "AlienVault OTX", "estructura": "estructura de los valores", "correlacion_nexo": "correlación de NEXO"}
INGESTA = {"creado": "nuevo", "existente": "reutilizado", "duplicado": "duplicado", "invalido": "inválido", "eliminado": "eliminado"}


def generate_batch_report(
    db: Session,
    batch: Batch,
    items: list[dict],
    investigaciones: list[dict],
    index: AttckIndex,
    vector_store: VectorStore,
) -> BatchReport:
    """Correlaciona el lote, redacta y persiste una versión nueva del informe. Sin commit.

    Solo lee lo persistido (`investigaciones` de construir()): no correlaciona ningún
    indicador ni sale a las fuentes. Una sola llamada al LLM, que nunca tumba el informe.
    """
    correlacion = correlacionar_lote(items, investigaciones, index)
    descartados = [{k: i[k] for k in ("posicion", "entrada", "ingesta", "motivo")} for i in items if i["indicator_id"] is None]
    ia = generate_batch_analysis(correlacion, vector_store, sobre=f"lote #{batch.id}")
    report = BatchReport(
        batch_id=batch.id,
        contenido=build_batch_report_content(batch, correlacion, descartados, ia),
        conclusion=correlacion["conclusion"]["nivel"],
        metadatos=json.dumps({"correlacion": correlacion, "descartados": descartados, "ia": ia}, ensure_ascii=False),
    )
    db.add(report)
    db.flush()
    return report


def _codigo(valor: str) -> str:
    """Valor como código en línea, apto para una celda de tabla (GFM escapa el | con \\)."""
    valor = valor.replace("|", "\\|")
    return f"`` {valor} ``" if "`" in valor else f"`{valor}`"


def _plural(n: int, singular: str, plural: str) -> str:
    return f"{n} {singular if n == 1 else plural}"


def _cabecera(batch: Batch, c: dict, descartados: list[dict]) -> list[str]:
    cobertura, conclusion = c["cobertura"], c["conclusion"]
    entradas = cobertura["validos"] + len(descartados)
    por_ingesta = [
        _plural(sum(1 for d in descartados if d["ingesta"] == ingesta), singular, plural)
        for ingesta, singular, plural in (("duplicado", "duplicada", "duplicadas"), ("invalido", "inválida", "inválidas"),
                                          ("eliminado", "eliminada", "eliminadas"))
        if any(d["ingesta"] == ingesta for d in descartados)
    ]
    if conclusion["nivel"] == "relacion_demostrable":
        resumen = "Relación demostrable en " + "; ".join(
            f"{a['id']} ({', '.join(a['indicadores'])}; confianza {a['confianza']})" for a in c["agrupaciones"]
        )
    else:
        resumen = SIN_RELACION.rstrip(".")
    pendientes = cobertura["sin_correlacionar"] + cobertura["sin_enriquecer"]
    sin_verificar = [f"{f['etiqueta']} no verificó {', '.join(f['sin_verificar'])}" for f in cobertura["fuentes"] if f["sin_verificar"]]
    detalle_cobertura = "; ".join(
        ([f"pendientes: {', '.join(pendientes)}"] if pendientes else []) + sin_verificar
    ) or "todas las fuentes respondieron para los indicadores procesados"
    severidades = [i["severidad"]["nivel"] for i in c["indicadores"] if i["severidad"]]
    distribucion = " · ".join(f"{severidades.count(n)} {SEVERIDAD[n].lower()}" for n in SEVERIDAD if n in severidades)
    campos = [
        f"**Generado:** {datetime.now(timezone.utc).isoformat()}",
        f"**Indicadores:** {cobertura['validos']} válido(s) de {entradas} entrada(s)"
        + (f" ({', '.join(por_ingesta)})" if por_ingesta else ""),
        f"**Conclusión (NEXO, determinística):** {resumen}",
        f"**Cobertura:** {cobertura['nivel']} — {detalle_cobertura}",
        f"**Severidad por indicador:** {distribucion or 'ningún indicador procesado'}",
    ]
    titulo = f"# Informe conjunto — lote #{batch.id}" + (f": {batch.nombre}" if batch.nombre else "")
    # "  \n" es un salto de línea duro en Markdown (como en el informe individual).
    return [titulo, "", "  \n".join(campos)]


def _seccion_conclusion(c: dict) -> list[str]:
    conclusion, refs = c["conclusion"], {i["ref"]: i for i in c["indicadores"]}
    if conclusion["nivel"] == "sin_relacion_demostrable":
        lineas = [
            f"> **{SIN_RELACION}**{conclusion['texto'][len(SIN_RELACION):]}",
            ">",
            "> La ausencia de relación es un resultado válido, no un error del sistema.",
        ]
    else:
        lineas = [conclusion["texto"], ""]
        for a in c["agrupaciones"]:
            miembros = ", ".join(f"{r} {_codigo(refs[r]['valor'])}" for r in a["indicadores"])
            lineas.append(
                f"- **{a['id']}** (confianza {a['confianza']}): {miembros} — vínculos {', '.join(a['vinculos'])}; "
                f"{_plural(len(a['tecnicas_comunes']), 'técnica común', 'técnicas comunes')}."
            )
        if conclusion["aislados"]:
            lineas.append(f"- **Sin relación demostrable con el resto:** {', '.join(conclusion['aislados'])}.")
    return lineas


def _seccion_indicadores(c: dict) -> list[str]:
    lineas = [
        "| Ref | Indicador | Tipo | Ingesta | Entidad (asociación) | Confianza | Severidad | Con evidencia en | Cobertura |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for i in c["indicadores"]:
        entidad = f"{i['entidad']['nombre']} ({i['entidad']['tipo']}) · {i['asociacion']}" if i["entidad"] else "—"
        con_evidencia = ", ".join(f["etiqueta"] for f in i["fuentes"] if f["estado"] == "con_evidencia") or "—"
        lineas.append(
            f"| {i['ref']} | {_codigo(i['valor'])} | {i['tipo']} | {INGESTA[i['ingesta']]} | {entidad} | "
            f"{CONFIANZA[i['confianza']['nivel']] if i['confianza'] else '—'} | "
            f"{SEVERIDAD[i['severidad']['nivel']] if i['severidad'] else '—'} | {con_evidencia} | {i['cobertura'] or '—'} |"
        )
    contradicciones = [f"- ⚠ {i['ref']}: {x['detalle']}." for i in c["indicadores"] for x in i["contradicciones"]]
    return lineas + (["", "**Contradicciones entre fuentes:**", "", *contradicciones] if contradicciones else [])


def _senal(s: dict) -> str:
    texto = f"**{SENAL[s['tipo']]}** ({ORIGEN[s['origen']]}): {s['detalle']}"
    if s["tipo"] == "pulse_compartido":
        # Solo ids: el nombre del pulse es texto libre de terceros y no entra al informe.
        texto += " — " + ", ".join(f"`{p['id']}`" for p in s["pulses"])
    return texto.replace("|", "\\|")


def _seccion_vinculos(c: dict) -> list[str]:
    if not c["vinculos"]:
        lineas = ["Ningún par de indicadores comparte evidencia."]
    else:
        lineas = ["| Vínculo | Indicadores | Señales | Confianza |", "|---|---|---|---|"]
        lineas += [
            f"| {v['id']} | {v['a']} – {v['b']} | {'; '.join(_senal(s) for s in v['senales'])} | {v['confianza']} |"
            for v in c["vinculos"]
        ]
    return lineas + [
        "",
        "Confianza: **alta** con señales fuertes de dos orígenes distintos; **media** con uno; **baja** con solo la "
        "misma entidad, que no basta para agrupar.",
        "",
        "**No se consideran señal:** técnicas o tácticas compartidas, etiquetas, nombres de pulses, países ni ASN.",
    ]


def _seccion_cadena(c: dict) -> list[str]:
    if not c["cadena_ataque"]:
        return ["Ningún indicador tiene entidad atribuida: no hay técnicas que mostrar."]
    lineas = [
        "> Técnicas documentadas en MITRE ATT&CK para las entidades del lote, no comportamiento observado.",
        "> Que dos entidades compartan una técnica **no** prueba relación entre sus indicadores.",
    ]
    for grupo in c["cadena_ataque"]:
        lineas += ["", f"### {grupo['tactica']}", ""]
        for t in grupo["tecnicas"]:
            nota = f" · documentada para {', '.join(t['entidades'])}" if t["varias_entidades"] else ""
            lineas.append(f"- {t['id']} {t['nombre']} — {', '.join(t['indicadores'])}{nota}")
    varias = sum(t["varias_entidades"] for g in c["cadena_ataque"] for t in g["tecnicas"])
    lineas += [""] + [
        f"**Técnicas comunes en {a['id']}:** {len(a['tecnicas_comunes'])}." for a in c["agrupaciones"]
    ] + [f"**Documentadas para más de una entidad:** {varias} (no prueba relación)."]
    return lineas


def _seccion_no_participan(c: dict, descartados: list[dict]) -> list[str]:
    motivo = {
        "sin_entidad": "sin entidad atribuible",
        "sin_correlacionar": "enriquecido, pero falta ejecutar /correlate",
        "sin_enriquecer": "sin enriquecer: pendiente, o ninguna fuente respondió",
    }
    filas = []
    for i in c["indicadores"]:
        if i["estado"] == "participa":
            continue
        texto = motivo[i["estado"]]
        if i["severidad"]:
            texto += f" — severidad {SEVERIDAD[i['severidad']['nivel']].lower()}"
        filas.append(f"| {i['ref']} | {_codigo(i['valor'])} | {texto} |")
    for d in descartados:
        texto = INGESTA[d["ingesta"]] + (f": {d['motivo']}" if d["motivo"] else "")
        filas.append(f"| — | {_codigo(d['entrada'])} | {texto.replace('|', '/')} |")
    if not filas:
        return ["Todos los indicadores participan en la evaluación de vínculos."]
    return ["| Ref | Indicador | Motivo |", "|---|---|---|", *filas]


def _seccion_fuentes(c: dict) -> list[str]:
    lineas = []
    for f in c["cobertura"]["fuentes"]:
        total = len(f["verificados"]) + len(f["sin_verificar"])
        linea = f"- **{f['etiqueta']}:** verificó {len(f['verificados'])} de {total}"
        if f["sin_verificar"]:
            linea += f"; sin verificar: {', '.join(f['sin_verificar'])} (no significa sin evidencia)"
        lineas.append(linea + ".")
    reutilizados = [i["ref"] for i in c["indicadores"] if i["ingesta"] == "existente"]
    if reutilizados:
        lineas.append(
            f"- **Reutilizados de investigaciones previas:** {', '.join(reutilizados)}. Su evidencia sale de la caché, "
            "que no vence: puede ser antigua."
        )
    return lineas + [
        "- Solo se comparan los pulses que OTX lista para cada indicador.",
        "- La táctica de cada técnica es la primera que le asigna ATT&CK.",
    ]


def build_batch_report_content(batch: Batch, correlacion: dict, descartados: list[dict], ia: dict | None) -> str:
    secciones = [
        ("1. Conclusión", _seccion_conclusion(correlacion)),
        ("2. Indicadores", _seccion_indicadores(correlacion)),
        ("3. Vínculos entre indicadores", _seccion_vinculos(correlacion)),
        ("4. Cobertura ATT&CK conjunta", _seccion_cadena(correlacion)),
        ("5. Indicadores que no participan", _seccion_no_participan(correlacion, descartados)),
        ("6. Cobertura de fuentes y límites", _seccion_fuentes(correlacion)),
        ("7. Análisis", _seccion_analisis(ia)),
    ]
    lineas = _cabecera(batch, correlacion, descartados)
    for titulo, cuerpo in secciones:
        lineas += ["", f"## {titulo}", "", *cuerpo]
    return "\n".join(lineas) + "\n"
