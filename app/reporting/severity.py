"""Severidad y concordancia entre fuentes. Lógica pura y determinística: el LLM no decide
ninguna de las dos.

ponytail: los umbrales son perillas fijadas para el prototipo, no calibradas con datos de
un SOC real. Ajustarlos cuando haya casos etiquetados.
"""

from app.correlation.attck_loader import AttckIndex, find_entity

CONFIANZA_FUERTE = 0.9  # malware_families en la etapa (a)
VT_CRITICA = 10  # motores que marcan malicioso
VT_ALTA = 5
FUENTES_CONCORDANCIA = ("threatfox", "virustotal")  # OTX no: es la base de la correlación
FALLIDOS = {"error", "limite_cuota", "no_disponible"}


def _resumen(fuentes: list[dict], nombre: str) -> dict:
    return next((f.get("resumen") or {} for f in fuentes if f["fuente"] == nombre), {})


def calcular_severidad(correlacion: dict, fuentes: list[dict]) -> dict:
    """{nivel, motivos}. nivel: critica | alta | media | baja | benigno | indeterminada.

    Nunca "baja" si alguna fuente no se pudo verificar y nada muestra evidencia: eso es
    "indeterminada" (no pude verificar != verifiqué y no hay nada).
    """
    confianza = (correlacion["confianza"] or 0) if correlacion["resuelto"] else 0
    entidad = (correlacion.get("entity") or {}).get("nombre")
    vt = (_resumen(fuentes, "virustotal").get("detecciones") or {})
    vt_maliciosos, vt_sospechosos = vt.get("maliciosos") or 0, vt.get("sospechosos") or 0
    tf = _resumen(fuentes, "threatfox")
    otx = _resumen(fuentes, "alienvault_otx")
    pulses = (otx.get("detecciones") or {}).get("pulses") or 0

    motivos = []
    if correlacion["resuelto"]:
        motivos.append(f"asociado a {entidad} con confianza {confianza}")
    if vt_maliciosos or vt_sospechosos:
        motivos.append(f"VirusTotal: {vt_maliciosos} motores maliciosos, {vt_sospechosos} sospechosos")
    if tf.get("tiene_evidencia"):
        familias = ", ".join(tf.get("familias") or []) or "sin familia"
        motivos.append(f"ThreatFox lo registra ({familias})")
    if pulses and not correlacion["resuelto"]:
        motivos.append(f"{pulses} pulse(s) en OTX sin entidad atribuible")

    fuerte = correlacion["resuelto"] and confianza >= CONFIANZA_FUERTE
    if fuerte and (vt_maliciosos >= VT_CRITICA or tf.get("tiene_evidencia")):
        nivel = "critica"
    elif fuerte or vt_maliciosos >= VT_ALTA or tf.get("tiene_evidencia"):
        nivel = "alta"
    elif correlacion["resuelto"] or vt_maliciosos or vt_sospechosos or pulses:
        nivel = "media"
    elif otx.get("veredicto") == "benigno_conocido":
        nivel, motivos = "benigno", ["OTX lo tiene en lista blanca y ninguna fuente lo reporta"]
    elif fallidas := [f["etiqueta"] for f in fuentes if f["estado"] in FALLIDOS]:
        nivel, motivos = "indeterminada", [f"no se pudo verificar en: {', '.join(fallidas)}"]
    elif fuentes and all(f["estado"] == "omitido" for f in fuentes):
        nivel, motivos = "indeterminada", ["dirección no pública: no se consultó a fuentes externas"]
    else:
        nivel, motivos = "baja", ["ninguna fuente consultada tiene registros del indicador"]
    return {"nivel": nivel, "motivos": motivos}


def calcular_concordancia(correlacion: dict, fuentes: list[dict], index: AttckIndex) -> list[dict]:
    """¿Las familias que reportan ThreatFox y VirusTotal coinciden con la entidad de NEXO?

    Cada familia se resuelve contra ATT&CK (nombre o alias), igual que en la etapa (a).
    resultado: concuerda | discrepa | sugiere (NEXO no resolvió, la fuente sí apunta a una
    entidad ATT&CK) | no_comparable (la fuente no trae familias reconocibles en ATT&CK).
    """
    entidad = (correlacion.get("entity") or {}).get("nombre") if correlacion["resuelto"] else None
    salida = []
    for f in fuentes:
        if f["fuente"] not in FUENTES_CONCORDANCIA or not f.get("resumen"):
            continue
        familias = f["resumen"].get("familias") or []
        entidades = sorted({e for fam in familias if (e := find_entity(index, fam))})
        if not entidades:
            resultado = "no_comparable"
        elif entidad is None:
            resultado = "sugiere"
        elif entidad in entidades:
            resultado = "concuerda"
        else:
            resultado = "discrepa"
        salida.append({
            "fuente": f["fuente"], "etiqueta": f["etiqueta"], "familias": familias,
            "entidades": entidades, "resultado": resultado,
        })
    return salida
