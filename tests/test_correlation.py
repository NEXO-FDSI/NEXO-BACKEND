"""Correlación en dos etapas. Usa el AttckIndex sintético del conftest."""

import json
from unittest.mock import patch

import pytest

from app.correlation.service import (
    correlate_indicator,
    resolve_entity_from_enrichment,
    retrieve_techniques_for_entity,
)
from app.db.repositories import (
    entity_repository,
    entity_technique_link_repository,
    indicator_entity_link_repository,
    indicator_repository,
)
from app.db.repositories.enrichment_cache import enrichment_cache_repository
from app.enrichment.service import FUENTE

RETRIEVE = "app.correlation.service.retrieve_techniques_for_entity"


def _detalle(*, familias=(), tags=(), nombre_pulse="Informe suelto"):
    return {"pulse_info": {"count": 1, "pulses": [{
        "name": nombre_pulse,
        "malware_families": [{"display_name": f} for f in familias],
        "tags": list(tags),
    }]}}


def _indicador(db, valor="1.2.3.4"):
    return indicator_repository.create(db, {"tipo": "ip", "valor": valor})


def _cachear(db, indicator, detalle):
    return enrichment_cache_repository.create(db, {
        "indicator_id": indicator.id, "fuente_api": FUENTE,
        "respuesta_json": json.dumps(detalle)})


# --- EL TEST CRÍTICO ---


def test_sin_evidencia_la_etapa_b_nunca_se_invoca(db, attck_index):
    """Si (a) no resuelve, retrieve_techniques_for_entity no debe llamarse jamás."""
    ind = _indicador(db)
    antes_ent = len(entity_repository.list(db))
    antes_link = len(indicator_entity_link_repository.list(db))

    with patch(RETRIEVE) as mock:
        resultado = correlate_indicator(db, ind, {"pulse_info": {"count": 0, "pulses": []}}, attck_index)

    assert mock.call_count == 0, "la etapa (b) se ejecutó sin entidad resuelta"
    assert resultado == {"resuelto": False, "entity": None, "confianza": None,
                         "evidencia": None, "tecnicas": []}
    assert len(entity_repository.list(db)) == antes_ent
    assert len(indicator_entity_link_repository.list(db)) == antes_link


def test_candidato_que_no_existe_en_attck_tampoco_invoca_la_etapa_b(db, attck_index):
    ind = _indicador(db)
    with patch(RETRIEVE) as mock:
        r = correlate_indicator(db, ind, _detalle(familias=["MalwareInexistente"]), attck_index)
    assert mock.call_count == 0 and r["resuelto"] is False


# --- resolución (etapa a) ---


def test_malware_families_da_confianza_09(attck_index):
    r = resolve_entity_from_enrichment(_detalle(familias=["Emotet"]), attck_index)
    assert r["nombre_canonico"] == "emotet" and r["confianza"] == 0.9
    assert "malware_families" in r["evidencia"] and "Emotet" in r["evidencia"]


def test_tags_da_confianza_06(attck_index):
    r = resolve_entity_from_enrichment(_detalle(tags=["apt-falso"]), attck_index)
    assert r["nombre_canonico"] == "apt-falso" and r["confianza"] == 0.6
    assert "tags" in r["evidencia"]


def test_malware_families_gana_a_tags(attck_index):
    r = resolve_entity_from_enrichment(_detalle(familias=["Emotet"], tags=["apt-falso"]), attck_index)
    assert r["nombre_canonico"] == "emotet" and r["confianza"] == 0.9


def test_el_nombre_del_pulse_no_es_candidato(attck_index):
    """name es texto libre: usarlo es la vía directa a la atribución incorrecta."""
    assert resolve_entity_from_enrichment(_detalle(nombre_pulse="Emotet campaign"), attck_index) is None


def test_alias_resuelve_al_canonico(attck_index):
    r = resolve_entity_from_enrichment(_detalle(familias=["Geodo"]), attck_index)
    assert r["nombre_canonico"] == "emotet"


def test_nombre_ambiguo_deja_constancia_en_la_evidencia(attck_index):
    r = resolve_entity_from_enrichment(_detalle(familias=["Ambigua"]), attck_index)
    assert "ambiguo" in r["evidencia"] and "grupo, malware" in r["evidencia"]


# --- correlación completa (etapas a + b) ---


def test_caso_positivo_persiste_todo(db, attck_index):
    ind = _indicador(db)
    r = correlate_indicator(db, ind, _detalle(familias=["Emotet"]), attck_index)

    assert r["resuelto"] is True and r["confianza"] == 0.9
    assert r["entity"]["nombre"] == "emotet" and r["entity"]["tipo"] == "malware"
    assert [t["id"] for t in r["tecnicas"]] == ["T9001", "T9002"]
    assert r["tecnicas"][0] == {"id": "T9001", "nombre": "Falsa Uno", "tactica": "Initial Access"}

    link = indicator_entity_link_repository.list(db)
    assert len(link) == 1 and link[0].confianza == 0.9
    enlaces = entity_technique_link_repository.list(db)
    assert len(enlaces) == 2
    assert all("MITRE ATT&CK" in e.fuente_attck for e in enlaces)


def test_entidad_ambigua_recupera_las_tecnicas_fusionadas(db, attck_index):
    ind = _indicador(db)
    r = correlate_indicator(db, ind, _detalle(familias=["Ambigua"]), attck_index)
    assert sorted(t["id"] for t in r["tecnicas"]) == ["T9001", "T9003"]


def test_idempotente(db, attck_index):
    ind = _indicador(db)
    primero = correlate_indicator(db, ind, _detalle(familias=["Emotet"]), attck_index)
    segundo = correlate_indicator(db, ind, _detalle(familias=["Emotet"]), attck_index)

    assert primero == segundo
    assert len(entity_repository.list(db)) == 1
    assert len(indicator_entity_link_repository.list(db)) == 1
    assert len(entity_technique_link_repository.list(db)) == 2


def test_retrieve_es_puro(attck_index):
    assert retrieve_techniques_for_entity("emotet", attck_index) == ["T9001", "T9002"]
    assert retrieve_techniques_for_entity("no-existe", attck_index) == []


# --- endpoint ---


def test_endpoint_200_resuelto(client, db):
    ind = _indicador(db, "5.5.5.5")
    _cachear(db, ind, _detalle(familias=["Emotet"]))

    r = client.post(f"/indicators/{ind.id}/correlate")
    cuerpo = r.json()
    assert r.status_code == 200 and cuerpo["resuelto"] is True
    assert cuerpo["indicator_id"] == ind.id
    assert len(cuerpo["tecnicas"]) == 2


def test_endpoint_200_sin_evidencia(client, db):
    ind = _indicador(db, "6.6.6.6")
    _cachear(db, ind, {"pulse_info": {"count": 0, "pulses": []}})

    r = client.post(f"/indicators/{ind.id}/correlate")
    assert r.status_code == 200
    assert r.json()["resuelto"] is False and r.json()["tecnicas"] == []


def test_endpoint_400_sin_enriquecimiento_previo(client, db):
    ind = _indicador(db, "7.7.7.7")
    r = client.post(f"/indicators/{ind.id}/correlate")
    assert r.status_code == 400
    assert "/enrich" in r.json()["detail"]


def test_endpoint_404(client):
    assert client.post("/indicators/999999/correlate").status_code == 404
