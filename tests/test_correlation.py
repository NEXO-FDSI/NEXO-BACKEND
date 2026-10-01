"""Correlación en dos etapas. Usa el AttckIndex sintético del conftest."""

import json
from unittest.mock import patch

import pytest
from sqlalchemy import event

from app.correlation.attck_loader import AttckIndex

from app.correlation.service import (
    MAX_INDICADORES_PULSE,
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
                         "evidencia": None, "fuentes": [], "tecnicas": []}
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


# --- robustez frente a pulses agregados (hallazgo de la Etapa 9 con datos reales) ---


def _pulses(*pulses):
    """pulses: tuplas (familias, tags, indicator_count)."""
    return {"pulse_info": {"count": len(pulses), "pulses": [
        {"name": "x", "malware_families": [{"display_name": f} for f in fams],
         "tags": list(tags), "indicator_count": n}
        for fams, tags, n in pulses]}}


def test_pulse_masivo_no_aporta_candidatos(attck_index):
    """Caso real: un volcado de miles de indicadores con familia 'Cobalt Strike' le ganaba
    con 0.9 al tag 'wannacry' de los reportes enfocados."""
    r = resolve_entity_from_enrichment(
        _pulses((["Emotet"], [], MAX_INDICADORES_PULSE + 1), ([], ["apt-falso"], 17)), attck_index)
    assert r["nombre_canonico"] == "apt-falso" and r["confianza"] == 0.6
    assert "1 pulse(s) masivo(s) descartado(s)" in r["evidencia"]


def test_pulse_en_el_umbral_se_conserva(attck_index):
    r = resolve_entity_from_enrichment(_pulses((["Emotet"], [], MAX_INDICADORES_PULSE)), attck_index)
    assert r["nombre_canonico"] == "emotet" and "descartado" not in r["evidencia"]


def test_solo_pulses_masivos_no_fuerza_asociacion(attck_index):
    detalle = _pulses((["Emotet"], ["apt-falso"], 50_000))
    assert resolve_entity_from_enrichment(detalle, attck_index) is None


def test_gana_la_entidad_respaldada_por_mas_pulses(attck_index):
    r = resolve_entity_from_enrichment(
        _pulses((["Emotet"], [], 10), (["APT-Falso"], [], 10), (["apt-falso"], [], 10)), attck_index)
    assert r["nombre_canonico"] == "apt-falso"
    assert "'APT-Falso' (respaldado por 2 pulse(s))" in r["evidencia"]


def test_un_pulse_vota_una_sola_vez_por_entidad(attck_index):
    """Emotet y su alias Geodo repetidos en un pulse no suman más que un pulse aparte;
    empatados, gana el que apareció primero."""
    r = resolve_entity_from_enrichment(
        _pulses((["Emotet", "Geodo", "Emotet"], [], 10), (["apt-falso"], [], 10)), attck_index)
    assert r["nombre_canonico"] == "emotet" and "respaldado por 1 pulse(s)" in r["evidencia"]


# --- correlación completa (etapas a + b) ---


def test_caso_positivo_persiste_todo(db, attck_index):
    ind = _indicador(db)
    r = correlate_indicator(db, ind, _detalle(familias=["Emotet"]), attck_index)

    assert r["resuelto"] is True and r["confianza"] == 0.9
    assert r["entity"]["nombre"] == "emotet" and r["entity"]["tipo"] == "malware"
    assert [t["id"] for t in r["tecnicas"]] == ["T9001", "T9002"]
    assert r["fuentes"] == ["alienvault_otx"]
    assert r["tecnicas"][0] == {"id": "T9001", "nombre": "Falsa Uno", "tactica": "Initial Access",
                                "fuentes": ["alienvault_otx"], "reportada_por": []}

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


def test_queries_constantes_sin_importar_el_numero_de_tecnicas(db):
    """Fase 1 de evolución: antes eran ~6 queries por técnica (552 para Lazarus Group)."""
    def _indice(n):
        ids = [f"T{8000 + i}" for i in range(n)]
        return AttckIndex(
            techniques={t: {"nombre": t, "tactica": "Execution"} for t in ids},
            entity_type={"masiva": "grupo"},
            entity_techniques={"masiva": ids},
        )

    def _contar(valor, index):
        ind = _indicador(db, valor)
        conteo = []
        escucha = lambda *args, **kwargs: conteo.append(1)  # noqa: E731
        event.listen(db.bind, "before_cursor_execute", escucha)
        try:
            r = correlate_indicator(db, ind, _detalle(familias=["Masiva"]), index)
        finally:
            event.remove(db.bind, "before_cursor_execute", escucha)
        return len(conteo), r

    pocas, _ = _contar("1.1.1.1", _indice(3))
    muchas, r = _contar("2.2.2.2", _indice(100))
    assert len(r["tecnicas"]) == 100
    assert muchas <= pocas + 2, f"{muchas} queries para 100 técnicas vs {pocas} para 3"
    assert len(entity_technique_link_repository.list(db, limit=200)) == 100


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
