"""Índice en memoria del dataset STIX de MITRE ATT&CK. Lógica pura, sin FastAPI ni BD."""

import json
from dataclasses import dataclass, field

# STIX type -> tipo interno (el mismo vocabulario que usa entities.tipo)
_TIPOS_ENTIDAD = {
    "malware": "malware",
    "intrusion-set": "grupo",
    "tool": "herramienta",
    "campaign": "campaña",
}
# Precedencia al fusionar entidades homónimas: decide qué 'tipo' se registra.
_PRECEDENCIA = ("grupo", "malware", "herramienta", "campaña")


@dataclass
class AttckIndex:
    techniques: dict[str, dict] = field(default_factory=dict)
    entity_type: dict[str, str] = field(default_factory=dict)
    entity_aliases: dict[str, str] = field(default_factory=dict)
    entity_techniques: dict[str, list[str]] = field(default_factory=dict)
    # nombre ambiguo -> tipos fusionados. Permite dejar la fusión escrita en la
    # evidencia en vez de que ocurra en silencio.
    ambiguous: dict[str, list[str]] = field(default_factory=dict)


def _vivo(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _attck_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def _tactica(obj: dict) -> str | None:
    fases = obj.get("kill_chain_phases") or []
    if not fases:
        return None
    # Solo la primera fase: techniques.tactica admite una sola. Simplificación del spec;
    # 195 de las 697 técnicas vivas tienen más de una.
    return fases[0]["phase_name"].replace("-", " ").title()


def load_attck_index(path: str) -> AttckIndex:
    """Parsea el bundle STIX una sola vez y construye el índice."""
    with open(path, encoding="utf-8") as f:
        objetos = json.load(f)["objects"]

    # Todos los objetos: las relationship referencian por id STIX interno.
    por_id = {o["id"]: o for o in objetos}
    index = AttckIndex()

    for obj in objetos:
        if obj.get("type") != "attack-pattern" or not _vivo(obj):
            continue
        tid, tactica = _attck_id(obj), _tactica(obj)
        if tid and tactica:
            index.techniques[tid] = {"nombre": obj["name"], "tactica": tactica}

    # --- entidades ---
    alias_a_nombres: dict[str, set[str]] = {}
    for obj in objetos:
        tipo = _TIPOS_ENTIDAD.get(obj.get("type", ""))
        if tipo is None or not _vivo(obj):
            continue
        nombre = obj["name"].lower()

        anterior = index.entity_type.get(nombre)
        if anterior is None:
            index.entity_type[nombre] = tipo
        elif anterior != tipo:
            # Homónimos entre tipos (carbanak, akira, machete...): se fusionan.
            tipos = sorted({anterior, tipo}, key=_PRECEDENCIA.index)
            index.entity_type[nombre] = tipos[0]
            index.ambiguous[nombre] = tipos

        # malware/tool usan x_mitre_aliases; campaign/intrusion-set usan aliases.
        for alias in obj.get("aliases") or obj.get("x_mitre_aliases") or []:
            alias = alias.lower()
            if alias != nombre:  # los alias incluyen el propio name
                alias_a_nombres.setdefault(alias, set()).add(nombre)

    # Un alias que apunta a dos entidades distintas no identifica a ninguna: se descarta.
    for alias, nombres in alias_a_nombres.items():
        if len(nombres) == 1 and alias not in index.entity_type:
            index.entity_aliases[alias] = next(iter(nombres))

    # --- relaciones entidad -> técnica ---
    for obj in objetos:
        if obj.get("type") != "relationship" or obj.get("relationship_type") != "uses":
            continue
        if not _vivo(obj):
            continue
        origen, destino = por_id.get(obj["source_ref"]), por_id.get(obj["target_ref"])
        if origen is None or destino is None:
            continue
        if origen.get("type") not in _TIPOS_ENTIDAD or destino.get("type") != "attack-pattern":
            continue
        if not _vivo(origen) or not _vivo(destino):
            continue

        tid = _attck_id(destino)
        if tid is None or tid not in index.techniques:
            continue
        tecnicas = index.entity_techniques.setdefault(origen["name"].lower(), [])
        if tid not in tecnicas:  # homónimos fusionan aquí, sin duplicar
            tecnicas.append(tid)

    return index


def find_entity(index: AttckIndex, candidate: str) -> str | None:
    """Nombre canónico de la entidad que coincide con el candidato, o None."""
    if not candidate:
        return None
    clave = candidate.strip().lower()
    if clave in index.entity_type:
        return clave
    return index.entity_aliases.get(clave)
