"""Correlación en dos etapas: (a) resolución de entidad, (b) recuperación de técnicas.

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
from app.db.repositories.indicator_entity_link import get_by_indicator, get_by_indicator_and_entity
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


def _mas_respaldada(por_pulse: list[list[str]], index: AttckIndex) -> tuple[str, str, int] | None:
    """(canónico, candidato textual, nº de pulses que lo respaldan) de la entidad con más
    pulses distintos a favor. Empate: gana la que apareció primero."""
    soporte: dict[str, int] = {}  # dict conserva el orden de aparición
    texto: dict[str, str] = {}
    for candidatos in por_pulse:
        en_este_pulse = set()
        for candidato in candidatos:
            canonico = find_entity(index, candidato)
            if canonico is None or canonico in en_este_pulse:
                continue
            en_este_pulse.add(canonico)
            soporte[canonico] = soporte.get(canonico, 0) + 1
            texto.setdefault(canonico, candidato)
    if not soporte:
        return None
    ganador = max(soporte, key=soporte.__getitem__)  # max devuelve el primero entre empatados
    return ganador, texto[ganador], soporte[ganador]


def resolve_entity_from_enrichment(detalle: dict, index: AttckIndex) -> dict | None:
    """Etapa (a). Devuelve la entidad resuelta con su evidencia, o None."""
    familias, tags, descartados = _candidatos(detalle)

    for por_pulse, confianza, ruta in (
        (familias, CONFIANZA_MALWARE_FAMILIES, "pulse_info.pulses[].malware_families[].display_name"),
        (tags, CONFIANZA_TAGS, "pulse_info.pulses[].tags[]"),
    ):
        ganador = _mas_respaldada(por_pulse, index)
        if ganador is None:
            continue
        canonico, candidato, soporte = ganador
        evidencia = f"{ruta} = '{candidato}' (respaldado por {soporte} pulse(s)"
        if descartados:
            evidencia += f"; {descartados} pulse(s) masivo(s) descartado(s)"
        evidencia += ")"
        if canonico in index.ambiguous:
            tipos = ", ".join(index.ambiguous[canonico])
            evidencia += f" (nombre ambiguo en ATT&CK: {tipos} — técnicas fusionadas)"
        return {
            "nombre_canonico": canonico,
            "tipo": index.entity_type[canonico],
            "confianza": confianza,
            "evidencia": evidencia,
        }

    return None  # evidencia insuficiente: no se fuerza ninguna asociación


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
    return {"resuelto": False, "entity": None, "confianza": None, "evidencia": None, "tecnicas": []}


def _tecnicas_de(nombre: str, index: AttckIndex) -> list[dict]:
    return [
        {"id": tid, **index.techniques[tid]}
        for tid in retrieve_techniques_for_entity(nombre, index)
        if tid in index.techniques
    ]


def correlation_snapshot(
    db: Session, indicator: Indicator, detalle: dict, index: AttckIndex
) -> dict | None:
    """Lo que devolvió (o devolvería) /correlate, SIN escribir nada: para reconstruir una
    investigación con GET. None si la correlación aún no se ejecutó.

    Con link de la etapa (a) se reconstruye desde él (entidad, confianza y evidencia
    persistidas). Sin link, la correlación es determinística sobre la caché de OTX: si la
    etapa (a) no resuelve, /correlate daría "sin asociación"; si resuelve, es que todavía
    no se ejecutó (al ejecutarse habría creado el link).
    """
    link = get_by_indicator(db, indicator.id)
    if link is None:
        return _sin_asociacion() if resolve_entity_from_enrichment(detalle, index) is None else None
    entity = link.entity
    return {
        "resuelto": True,
        "entity": {"id": entity.id, "nombre": entity.nombre, "tipo": entity.tipo},
        "confianza": link.confianza,
        "evidencia": link.evidencia,
        "tecnicas": _tecnicas_de(entity.nombre, index),
    }


def correlate_indicator(
    db: Session, indicator: Indicator, detalle: dict, index: AttckIndex
) -> dict:
    resuelto = resolve_entity_from_enrichment(detalle, index)

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

    tecnicas = _tecnicas_de(nombre, index)
    _persistir_tecnicas(db, entity.id, [t["id"] for t in tecnicas], index)

    return {
        "resuelto": True,
        "entity": {"id": entity.id, "nombre": entity.nombre, "tipo": entity.tipo},
        "confianza": resuelto["confianza"],
        "evidencia": resuelto["evidencia"],
        "tecnicas": tecnicas,
    }
