"""Correlación en dos etapas: (a) resolución de entidad, (b) recuperación de técnicas.

La etapa (b) nunca se ejecuta si (a) no resolvió. Eso es verificable por inspección:
correlate_indicator hace un return temprano antes de cualquier llamada a
retrieve_techniques_for_entity.
"""

from sqlalchemy.orm import Session

from app.correlation.attck_loader import AttckIndex, find_entity
from app.db.models import Indicator
from app.db.repositories import (
    entity_repository,
    entity_technique_link_repository,
    indicator_entity_link_repository,
    technique_repository,
)
from app.db.repositories.entity import get_by_nombre
from app.db.repositories.entity_technique_link import get_by_entity_and_technique
from app.db.repositories.indicator_entity_link import get_by_indicator_and_entity

FUENTE_ATTCK = "MITRE ATT&CK STIX dataset — relationship 'uses'"
CONFIANZA_MALWARE_FAMILIES = 0.9  # señal estructurada
CONFIANZA_TAGS = 0.6  # señal ruidosa


def _candidatos(detalle: dict) -> tuple[list[str], list[str]]:
    """Candidatos de las dos fuentes permitidas, en orden de prioridad.

    pulse_info.pulses[].name NO se usa: es texto libre del autor del pulse y es
    justamente la fuente que produce atribución incorrecta.
    """
    familias, tags = [], []
    for pulse in (detalle.get("pulse_info") or {}).get("pulses") or []:
        for familia in pulse.get("malware_families") or []:
            nombre = familia.get("display_name") if isinstance(familia, dict) else familia
            if nombre:
                familias.append(nombre)
        tags.extend(t for t in (pulse.get("tags") or []) if t)
    return familias, tags


def resolve_entity_from_enrichment(detalle: dict, index: AttckIndex) -> dict | None:
    """Etapa (a). Devuelve la entidad resuelta con su evidencia, o None."""
    familias, tags = _candidatos(detalle)

    for candidatos, confianza, ruta in (
        (familias, CONFIANZA_MALWARE_FAMILIES, "pulse_info.pulses[].malware_families[].display_name"),
        (tags, CONFIANZA_TAGS, "pulse_info.pulses[].tags[]"),
    ):
        for candidato in candidatos:
            canonico = find_entity(index, candidato)
            if canonico is None:
                continue
            evidencia = f"{ruta} = '{candidato}'"
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


def correlate_indicator(
    db: Session, indicator: Indicator, detalle: dict, index: AttckIndex
) -> dict:
    resuelto = resolve_entity_from_enrichment(detalle, index)

    if resuelto is None:
        # Corte de la cadena. Nada debajo de esta línea se ejecuta.
        return {
            "resuelto": False,
            "entity": None,
            "confianza": None,
            "evidencia": None,
            "tecnicas": [],
        }

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

    tecnicas = []
    for technique_id in retrieve_techniques_for_entity(nombre, index):
        datos = index.techniques.get(technique_id)
        if datos is None:
            continue
        # techniques debe existir antes del link: entity_technique_link.technique_id
        # tiene FK a techniques.id y el seed puede no haber corrido todavía.
        if technique_repository.get(db, technique_id) is None:
            technique_repository.create(db, {"id": technique_id, **datos})
        if get_by_entity_and_technique(db, entity.id, technique_id) is None:
            entity_technique_link_repository.create(
                db,
                {
                    "entity_id": entity.id,
                    "technique_id": technique_id,
                    "fuente_attck": FUENTE_ATTCK,
                },
            )
        tecnicas.append({"id": technique_id, **datos})

    return {
        "resuelto": True,
        "entity": {"id": entity.id, "nombre": entity.nombre, "tipo": entity.tipo},
        "confianza": resuelto["confianza"],
        "evidencia": resuelto["evidencia"],
        "tecnicas": tecnicas,
    }
