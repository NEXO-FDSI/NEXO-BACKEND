"""Severidad, concordancia, contradicciones y nivel de confianza. Lógica pura y
determinística: el LLM no decide ninguna.

ponytail: los umbrales son perillas fijadas para el prototipo, no calibradas con datos de
un SOC real. Ajustarlos cuando haya casos etiquetados.
"""

from app.correlation.attck_loader import AttckIndex, find_entity
from app.enrichment.providers.threatfox import CONFIANZA_MINIMA as TF_CONFIANZA_MINIMA
from app.enrichment.service import FALLIDOS, RESPONDIERON

CONFIANZA_FUERTE = 0.9  # malware_families en la etapa (a)
VT_CRITICA = 10  # motores que marcan malicioso
VT_ALTA = 5


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
    detecciones_otx = otx.get("detecciones") or {}
    # Solo pulses enfocados: los volcados agregados no son evidencia (Etapa 9).
    pulses = max((detecciones_otx.get("pulses") or 0) - (detecciones_otx.get("pulses_masivos") or 0), 0)
    tf_registra = bool(tf.get("tiene_evidencia"))
    # Un registro de ThreatFox solo sube la severidad con confianza suficiente; por debajo
    # (o sin confianza informada) cuenta como señal débil, igual que un pulse de OTX.
    tf_fuerte = tf_registra and (tf.get("confianza") or 0) >= TF_CONFIANZA_MINIMA

    motivos = []
    if correlacion["resuelto"]:
        motivos.append(f"asociado a {entidad} con confianza {confianza}")
    if vt_maliciosos or vt_sospechosos:
        motivos.append(f"VirusTotal: {vt_maliciosos} motores maliciosos, {vt_sospechosos} sospechosos")
    if tf_registra:
        familias = ", ".join(tf.get("familias") or []) or "sin familia"
        motivo = f"ThreatFox lo registra ({familias})"
        if not tf_fuerte:
            confianza_tf = f"{tf['confianza']}/100" if tf.get("confianza") is not None else "no informada"
            motivo += f" con confianza {confianza_tf}, por debajo del mínimo de {TF_CONFIANZA_MINIMA}"
        motivos.append(motivo)
    if pulses and not correlacion["resuelto"]:
        motivos.append(f"{pulses} pulse(s) en OTX sin entidad atribuible")

    fuerte = correlacion["resuelto"] and confianza >= CONFIANZA_FUERTE
    if fuerte and (vt_maliciosos >= VT_CRITICA or tf_fuerte):
        nivel = "critica"
    elif fuerte or vt_maliciosos >= VT_ALTA or tf_fuerte:
        nivel = "alta"
    elif correlacion["resuelto"] or vt_maliciosos or vt_sospechosos or pulses or tf_registra:
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
    """¿Las familias que reporta cada fuente coinciden con la entidad de NEXO?

    Cada familia se resuelve contra ATT&CK (nombre o alias), igual que en la etapa (a).
    resultado: concuerda | discrepa | sugiere (NEXO no resolvió, la fuente sí apunta a una
    entidad ATT&CK) | no_comparable (la fuente no trae familias reconocibles en ATT&CK).
    """
    entidad = (correlacion.get("entity") or {}).get("nombre") if correlacion["resuelto"] else None
    salida = []
    for f in fuentes:
        if not f.get("resumen"):
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


def _lista(etiquetas: list[str]) -> str:
    return " y ".join([", ".join(etiquetas[:-1]), etiquetas[-1]] if len(etiquetas) > 1 else etiquetas)


def detectar_contradicciones(fuentes: list[dict], concordancia: list[dict]) -> list[dict]:
    """Desacuerdos entre fuentes, para mostrarlos y no resolverlos en silencio.

    - entidad_distinta: las familias de una fuente apuntan a otra entidad de ATT&CK.
    - vt_limpio: VirusTotal analizó el indicador (hay motores) y ninguno lo detecta, pero
      otra fuente sí lo reporta.
    - lista_blanca: OTX lo tiene en lista blanca y otra fuente lo reporta.
    Que ThreatFox no lo tenga NO es contradicción: solo cubre IoCs recientes (es cobertura).
    """
    salida = [
        {
            "tipo": "entidad_distinta",
            "fuentes": [c["fuente"]],
            "detalle": f"{c['etiqueta']} reporta familias que ATT&CK asocia a "
                       f"{', '.join(c['entidades'])}, no a la entidad asociada",
        }
        for c in concordancia
        if c["resultado"] == "discrepa"
    ]
    por_nombre = {f["fuente"]: f for f in fuentes}
    con_evidencia = [f for f in fuentes if f["estado"] == "con_evidencia"]

    vt = por_nombre.get("virustotal") or {}
    total = ((vt.get("resumen") or {}).get("detecciones") or {}).get("total") or 0
    otras = [f for f in con_evidencia if f["fuente"] != "virustotal"]
    if vt.get("estado") == "sin_evidencia" and total and otras:
        salida.append({
            "tipo": "vt_limpio",
            "fuentes": ["virustotal", *(f["fuente"] for f in otras)],
            "detalle": f"VirusTotal: 0 de {total} motores lo detectan, pero "
                       f"{_lista([f['etiqueta'] for f in otras])} lo reporta(n)",
        })

    otx = por_nombre.get("alienvault_otx") or {}
    otras = [f for f in con_evidencia if f["fuente"] != "alienvault_otx"]
    if (otx.get("resumen") or {}).get("veredicto") == "benigno_conocido" and otras:
        salida.append({
            "tipo": "lista_blanca",
            "fuentes": ["alienvault_otx", *(f["fuente"] for f in otras)],
            "detalle": f"OTX lo tiene en lista blanca, pero {_lista([f['etiqueta'] for f in otras])} lo reporta(n)",
        })
    return salida


def calcular_confianza(correlacion: dict, fuentes: list[dict], contradicciones: list[dict]) -> dict:
    """{nivel, motivos}. Primera regla que aplica (documentada en el informe de la fase):

    sin_evidencia  ninguna fuente que respondió lo encontró (se dice si es completo o parcial)
    baja           hay contradicciones, o la evidencia es débil: sin entidad y una sola fuente,
                   o entidad inferida solo de etiquetas
    alta           entidad respaldada por 2 o más fuentes, sin contradicciones
    media          el resto: una fuente con familia de malware, o varias fuentes sin entidad común
    """
    etiqueta = {f["fuente"]: f["etiqueta"] for f in fuentes}
    con_evidencia = [f["etiqueta"] for f in fuentes if f["estado"] == "con_evidencia"]
    fallidas = [f["etiqueta"] for f in fuentes if f["estado"] in FALLIDOS]
    parcial = [f"no se pudo verificar en {_lista(fallidas)}: no significa sin evidencia"] if fallidas else []

    if not con_evidencia:
        respondieron = [f["etiqueta"] for f in fuentes if f["estado"] in RESPONDIERON]
        if respondieron:
            motivo = f"sin registros en {_lista(respondieron)}"
        elif fuentes and all(f["estado"] == "omitido" for f in fuentes):
            motivo = "dirección no pública: no se consultó a fuentes externas"
        else:
            motivo = "ninguna fuente respondió"
        return {"nivel": "sin_evidencia", "motivos": [motivo, *parcial]}

    resuelto = correlacion["resuelto"]
    entidad = (correlacion.get("entity") or {}).get("nombre")
    respaldo = [etiqueta.get(f, f) for f in correlacion.get("fuentes") or []] if resuelto else []

    if contradicciones:
        nivel, motivos = "baja", [c["detalle"] for c in contradicciones]
    elif not resuelto and len(con_evidencia) == 1:
        nivel, motivos = "baja", [f"solo {con_evidencia[0]} lo reporta y no hay entidad ATT&CK atribuible"]
    elif resuelto and (correlacion["confianza"] or 0) < CONFIANZA_FUERTE:
        nivel, motivos = "baja", [f"{entidad} se infiere solo de etiquetas ({_lista(respaldo)}): señal ruidosa"]
    elif resuelto and len(respaldo) >= 2:
        nivel, motivos = "alta", [f"{entidad} respaldada por {len(respaldo)} fuentes: {_lista(respaldo)}"]
    elif resuelto:
        nivel, motivos = "media", [f"{entidad} respaldada solo por {_lista(respaldo)} (familia de malware)"]
    else:
        nivel, motivos = "media", [
            f"{_lista(con_evidencia)} lo reportan, pero sin una entidad ATT&CK común"
        ]
    return {"nivel": nivel, "motivos": motivos + parcial}
