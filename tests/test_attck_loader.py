"""Carga del bundle STIX. Usa un bundle sintético, nunca el archivo real de 50 MB."""

import json

import pytest

from app.correlation.attck_loader import find_entity, load_attck_index


def _ap(stix_id, ext_id, nombre, fase, **extra):
    return {
        "type": "attack-pattern", "id": stix_id, "name": nombre,
        "external_references": [{"source_name": "mitre-attack", "external_id": ext_id}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": fase}],
        **extra,
    }


def _rel(origen, destino, **extra):
    return {
        "type": "relationship", "id": f"relationship--{origen[-4:]}-{destino[-4:]}",
        "relationship_type": "uses", "source_ref": origen, "target_ref": destino, **extra,
    }


BUNDLE = {"type": "bundle", "objects": [
    _ap("attack-pattern--0001", "T1001", "Phishing", "initial-access"),
    _ap("attack-pattern--0002", "T1002", "Shell", "command-and-control"),
    _ap("attack-pattern--0003", "T9999", "Revocada", "execution", revoked=True),
    _ap("attack-pattern--0004", "T9998", "Deprecada", "execution", x_mitre_deprecated=True),
    {"type": "malware", "id": "malware--0001", "name": "Emotet",
     "x_mitre_aliases": ["Emotet", "Geodo"]},
    {"type": "intrusion-set", "id": "intrusion-set--0001", "name": "APT-Falso",
     "aliases": ["APT-Falso", "Osito"]},
    {"type": "tool", "id": "tool--0001", "name": "Ambigua"},
    {"type": "malware", "id": "malware--0002", "name": "Ambigua"},
    {"type": "malware", "id": "malware--0003", "name": "Fantasma", "revoked": True},
    _rel("malware--0001", "attack-pattern--0001"),
    _rel("malware--0001", "attack-pattern--0002"),
    _rel("intrusion-set--0001", "attack-pattern--0001"),
    _rel("tool--0001", "attack-pattern--0001"),
    _rel("malware--0002", "attack-pattern--0002"),
    _rel("malware--0003", "attack-pattern--0001"),          # origen revocado
    _rel("malware--0001", "attack-pattern--0003"),          # destino revocado
    _rel("malware--0001", "intrusion-set--0001"),           # destino no es técnica
    _rel("malware--0001", "attack-pattern--0404"),          # destino inexistente
]}


@pytest.fixture
def index(tmp_path):
    ruta = tmp_path / "bundle.json"
    ruta.write_text(json.dumps(BUNDLE))
    return load_attck_index(str(ruta))


def test_tecnicas_vivas_con_tactica_capitalizada(index):
    assert set(index.techniques) == {"T1001", "T1002"}
    assert index.techniques["T1001"] == {"nombre": "Phishing", "tactica": "Initial Access"}
    assert index.techniques["T1002"]["tactica"] == "Command And Control"


def test_revocadas_y_deprecadas_quedan_fuera(index):
    assert "T9999" not in index.techniques and "T9998" not in index.techniques


def test_tipos_de_entidad_traducidos(index):
    assert index.entity_type["emotet"] == "malware"
    assert index.entity_type["apt-falso"] == "grupo"
    assert "fantasma" not in index.entity_type  # revocada


def test_alias_sin_autorreferencia(index):
    assert index.entity_aliases == {"geodo": "emotet", "osito": "apt-falso"}
    assert "emotet" not in index.entity_aliases


def test_homonimos_fusionan_tecnicas_y_quedan_anotados(index):
    assert index.ambiguous["ambigua"] == ["malware", "herramienta"]
    assert index.entity_type["ambigua"] == "malware"  # precedencia
    assert sorted(index.entity_techniques["ambigua"]) == ["T1001", "T1002"]


def test_relaciones_solo_entidad_a_tecnica_viva(index):
    assert index.entity_techniques["emotet"] == ["T1001", "T1002"]
    assert index.entity_techniques["apt-falso"] == ["T1001"]
    assert "fantasma" not in index.entity_techniques


def test_find_entity(index):
    assert find_entity(index, "EMOTET") == "emotet"
    assert find_entity(index, "  Geodo  ") == "emotet"   # alias, case y espacios
    assert find_entity(index, "desconocida") is None
    assert find_entity(index, "") is None
