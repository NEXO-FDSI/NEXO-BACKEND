"""Correlación en dos etapas: (a) resolución de entidad, (b) recuperación de técnicas.

La etapa (a) combina la evidencia de OTX, ThreatFox y VirusTotal; cada resultado guarda qué
fuentes lo sustentan (procedencia).

La etapa (b) nunca se ejecuta si (a) no resolvió. Eso es verificable por inspección:
correlate_indicator hace un return temprano antes de cualquier llamada a
retrieve_techniques_for_entity.
"""

from sqlalchemy.orm import Session

from app.correlation.attck_loader import AttckIndex, find_entity
from app.db.models import EntityTechniqueLink, Indicator, Technique
from app.db.repositories import entity_repository, indicator_entity_link_repository
from app.db.repositories.entity import get_by_nombre
from app.db.repositories.entity_technique_link import technique_ids_enlazadas
from app.db.repositories.indicator_entity_link import get_by_indicator_and_entity
from app.db.repositories.technique import ids_existentes

FUENTE_ATTCK = "MITRE ATT&CK STIX dataset — relationship 'uses'"
CONFIANZA_MALWARE_FAMILIES = 0.9  # señal estructurada
CONFIANZA_TAGS = 0.6  # señal ruidosa
# Un pulse con más indicadores que esto es un volcado agregado, no un reporte enfocado.
# Medido en la Etapa 9 sobre respuestas reales de OTX: los reportes enfocados tenían entre
# 3 y 378 indicadores; los volcados que secuestraban la atribución (un hash de WannaCry
# atribuido a Cobalt Strike con 0.9) tenían de 1.062 a más de un millón.
MAX_INDICADORES_PULSE = 1000


def _candidatos(detalle: dict) -> tuple[list[list[str]], list[list[str]], int]:
    """Candidatos por pulse de las dos fuentes permitidas, y cuántos pulses masivos se descartaron.

    pulse_info.pulses[].name NO se usa: es texto libre del autor del pulse y es
    justamente la fuente que produce atribución incorrecta.
    """
    familias, tags, descartados = [], [], 0
    for pulse in (detalle.get("pulse_info") or {}).get("pulses") or []:
        if (pulse.get("indicator_count") or 0) > MAX_INDICADORES_PULSE:
            descartados += 1
            continue
        familias.append([
            nombre
            for familia in pulse.get("malware_families") or []
            if (nombre := familia.get("display_name") if isinstance(familia, dict) else familia)
        ])
        tags.append([t for t in pulse.get("tags") or [] if t])
    return familias, tags, descartados


FUENTE_OTX = "alienvault_otx"  # literal: importar app.enrichment.service aquí sería circular
_RUTA_FAMILIAS_OTX = "pulse_info.pulses[].malware_families[].display_name"
_RUTA_TAGS_OTX = "pulse_info.pulses[].tags[]"


def _votos(detalle: dict, fuentes: list[dict]) -> tuple[list[tuple], list[tuple], int]:
    """(votos de familias, votos de etiquetas, pulses masivos descartados).

    Un voto = (fuente_api, ruta, candidatos). OTX vota una vez por pulse no masivo (como
    siempre); ThreatFox y VirusTotal, una vez cada una y solo si encontraron el indicador.
    De ellas se usa su resumen normalizado (familias y etiquetas ya saneadas).
    """
    familias, tags, descartados = _candidatos(detalle)
    votos_familias = [(FUENTE_OTX, _RUTA_FAMILIAS_OTX, c) for c in familias]
    votos_tags = [(FUENTE_OTX, _RUTA_TAGS_OTX, c) for c in tags]
    for f in fuentes:
        if f["fuente"] == FUENTE_OTX or f["estado"] != "con_evidencia" or not f.get("resumen"):
            continue
        votos_familias.append((f["fuente"], f"{f['etiqueta']} familias", f["resumen"]["familias"]))
        votos_tags.append((f["fuente"], f"{f['etiqueta']} etiquetas", f["resumen"]["etiquetas"]))
    return votos_familias, votos_tags, descartados


def _soporte(votos: list[tuple], index: AttckIndex) -> dict[str, dict[str, list]]:
    """canónico → {fuente_api: [ruta, candidato textual, nº de votos]}, en orden de aparición."""
    soporte: dict[str, dict[str, list]] = {}  # dict conserva el orden de aparición
    for fuente, ruta, candidatos in votos:
        en_este_voto = set()
        for candidato in candidatos:
            canonico = find_entity(index, candidato)
            if canonico is None or canonico in en_este_voto:
                continue
            en_este_voto.add(canonico)
            por_fuente = soporte.setdefault(canonico, {})
            if fuente in por_fuente:
                por_fuente[fuente][2] += 1
            else:
                por_fuente[fuente] = [ruta, candidato, 1]
    return soporte


def _describir_respaldo(fuente: str, ruta: str, candidato: str, votos: int, descartados: int) -> str:
    if fuente != FUENTE_OTX:
        return f"{ruta} = '{candidato}'"
    texto = f"{ruta} = '{candidato}' (respaldado por {votos} pulse(s)"
    if descartados:
        texto += f"; {descartados} pulse(s) masivo(s) descartado(s)"
    return texto + ")"


def resolve_entity_from_enrichment(detalle: dict, index: AttckIndex, fuentes: list[dict] = ()) -> dict | None:
    """Etapa (a) sobre la evidencia combinada. Devuelve la entidad resuelta, o None.

    detalle: respuesta cruda de OTX ({} si no la hay). fuentes: entradas de /enrich (con su
    resumen normalizado); de ellas aportan ThreatFox y VirusTotal.
    Gana la entidad respaldada por más fuentes distintas; desempate: más votos (pulses);
    luego la que apareció primero. Con solo OTX equivale a la regla de la Etapa 9.
    """
    familias, tags, descartados = _votos(detalle, list(fuentes))
    todas = _soporte(familias + tags, index)

    for votos, confianza in ((familias, CONFIANZA_MALWARE_FAMILIES), (tags, CONFIANZA_TAGS)):
        soporte = _soporte(votos, index)
        if not soporte:
            continue
        canonico = max(  # max devuelve el primero entre empatados
            soporte, key=lambda e: (len(soporte[e]), sum(v[2] for v in soporte[e].values()))
        )
        # Procedencia: las fuentes del nivel ganador y, detrás, las que solo lo nombran en
        # el otro nivel (p. ej. una etiqueta de VirusTotal que corrobora la familia de OTX).
        respaldo = dict(soporte[canonico])
        for fuente, dato in todas[canonico].items():
            respaldo.setdefault(fuente, dato)
        evidencia = "; ".join(_describir_respaldo(f, *dato, descartados) for f, dato in respaldo.items())
        if canonico in index.ambiguous:
            tipos = ", ".join(index.ambiguous[canonico])
            evidencia += f" (nombre ambiguo en ATT&CK: {tipos} — técnicas fusionadas)"
        return {
            "nombre_canonico": canonico,
            "tipo": index.entity_type[canonico],
            "confianza": confianza,
            "evidencia": evidencia,
            "fuentes": list(respaldo),
        }

    return None  # evidencia insuficiente: no se fuerza ninguna asociación


def procedencia_de(nombre: str, detalle: dict, index: AttckIndex, fuentes: list[dict] = ()) -> list[str]:
    """Fuentes cuya evidencia (familias o etiquetas) resuelve a esa entidad."""
    familias, tags, _ = _votos(detalle, list(fuentes))
    return list(_soporte(familias + tags, index).get(nombre, {}))


def retrieve_techniques_for_entity(nombre_canonico: str, index: AttckIndex) -> list[str]:
    """Etapa (b). Función pura: solo lee el índice, no toca la base de datos."""
    return list(index.entity_techniques.get(nombre_canonico, []))


def _persistir_tecnicas(db: Session, entity_id: int, ids: list[str], index: AttckIndex) -> None:
    """Crea las técnicas y los links que falten con dos SELECT en lote y un solo flush.

    Una consulta por técnica hacía 552 queries para Lazarus Group (93 técnicas): ~41 s
    contra Supabase a 75 ms por viaje (línea base de la Fase 0 de evolución).
    """
    if not ids:
        return
    existentes = ids_existentes(db, ids)
    enlazadas = technique_ids_enlazadas(db, entity_id, ids)
    # techniques debe existir antes del link (FK a techniques.id) y el seed puede no haber
    # corrido todavía: el unit of work de SQLAlchemy inserta Technique antes que el link.
    db.add_all(Technique(id=t, **index.techniques[t]) for t in ids if t not in existentes)
    db.add_all(
        EntityTechniqueLink(entity_id=entity_id, technique_id=t, fuente_attck=FUENTE_ATTCK)
        for t in ids
        if t not in enlazadas
    )
    db.flush()


def _sin_asociacion() -> dict:
    return {
        "resuelto": False, "entity": None, "confianza": None, "evidencia": None,
        "fuentes": [], "tecnicas": [],
    }


def _tecnicas_de(nombre: str, index: AttckIndex, procedencia: list[str], fuentes: list[dict]) -> list[dict]:
    """Técnicas de la entidad con su procedencia: `fuentes` = las que sustentan la entidad;
    `reportada_por` = las que además citan ese ID de ATT&CK. Un ID citado por una fuente
    nunca agrega una técnica: solo corrobora una de la cadena entidad → técnicas."""
    reportadas: dict[str, list[str]] = {}
    for f in fuentes:
        for tid in (f.get("resumen") or {}).get("tecnicas_attck") or []:
            reportadas.setdefault(tid, []).append(f["fuente"])
    return [
        {"id": tid, **index.techniques[tid], "fuentes": list(procedencia), "reportada_por": reportadas.get(tid, [])}
        for tid in retrieve_techniques_for_entity(nombre, index)
        if tid in index.techniques
    ]


def correlation_from_link(link, detalle: dict, index: AttckIndex, fuentes: list[dict] = ()) -> dict | None:
    """Lo que devolvió (o devolvería) /correlate, SIN escribir nada: para reconstruir una
    investigación con GET. None si la correlación aún no se ejecutó.

    Con link de la etapa (a) se reconstruye desde él (entidad, confianza y evidencia
    persistidas; la procedencia se recalcula de la caché). Sin link, la correlación es
    determinística sobre la caché de las fuentes: si la etapa (a) no resuelve, /correlate
    daría "sin asociación"; si resuelve, es que todavía no se ejecutó (al ejecutarse habría
    creado el link).
    """
    fuentes = list(fuentes)
    if link is None:
        return _sin_asociacion() if resolve_entity_from_enrichment(detalle, index, fuentes) is None else None
    entity = link.entity
    procedencia = procedencia_de(entity.nombre, detalle, index, fuentes)
    return {
        "resuelto": True,
        "entity": {"id": entity.id, "nombre": entity.nombre, "tipo": entity.tipo},
        "confianza": link.confianza,
        "evidencia": link.evidencia,
        "fuentes": procedencia,
        "tecnicas": _tecnicas_de(entity.nombre, index, procedencia, fuentes),
    }


def correlate_indicator(
    db: Session, indicator: Indicator, detalle: dict, index: AttckIndex, fuentes: list[dict] = ()
) -> dict:
    """detalle: respuesta cruda de OTX ({} si no la hay); fuentes: entradas de /enrich."""
    fuentes = list(fuentes)
    resuelto = resolve_entity_from_enrichment(detalle, index, fuentes)

    if resuelto is None:
        # Corte de la cadena. Nada debajo de esta línea se ejecuta.
        return _sin_asociacion()

    nombre = resuelto["nombre_canonico"]

    entity = get_by_nombre(db, nombre)
    if entity is None:
        entity = entity_repository.create(db, {"nombre": nombre, "tipo": resuelto["tipo"]})

    if get_by_indicator_and_entity(db, indicator.id, entity.id) is None:
        indicator_entity_link_repository.create(
            db,
            {
                "indicator_id": indicator.id,
                "entity_id": entity.id,
                "evidencia": resuelto["evidencia"],
                "confianza": resuelto["confianza"],
            },
        )

    tecnicas = _tecnicas_de(nombre, index, resuelto["fuentes"], fuentes)
    _persistir_tecnicas(db, entity.id, [t["id"] for t in tecnicas], index)

    return {
        "resuelto": True,
        "entity": {"id": entity.id, "nombre": entity.nombre, "tipo": entity.tipo},
        "confianza": resuelto["confianza"],
        "evidencia": resuelto["evidencia"],
        "fuentes": resuelto["fuentes"],
        "tecnicas": tecnicas,
    }
