"""DELETE /indicators/{id}: eliminación en cascada de todo lo que cuelga del indicador."""

import json

import pytest

from app.db.models import (
    EnrichmentCache,
    Entity,
    EntityTechniqueLink,
    HumanValidation,
    Indicator,
    IndicatorEntityLink,
    Report,
    Technique,
)

OTX_MOCK = "app.enrichment.client.fetch_reputation"


def _otx(familia):
    return {"pulse_info": {"count": 1, "pulses": [
        {"name": "p", "indicator_count": 10, "malware_families": [{"display_name": familia}], "tags": []}]}}


@pytest.fixture
def pipeline(client, vector_store, monkeypatch):
    """Corre el pipeline completo (OTX y LLM simulados) y devuelve el id del indicador."""
    vector_store.documentos = {
        t: {"document": f"{t} (x)\n\nTexto.", "metadata": {"nombre": t, "tactica": "x"}} for t in ("T9001", "T9002", "T9003")
    }
    salida = {"resumen": "ok", "hallazgos": []}
    monkeypatch.setattr("app.ai_component.service.generate_analysis",
                        lambda prompt, validar: (validar(json.dumps(salida)), {
                            "proveedor": "p", "modelo": "m", "latencia_ms": 1, "tokens": {}, "intentos_fallidos": []}))

    def correr(valor, familia="Emotet", validaciones=1):
        monkeypatch.setattr(OTX_MOCK, lambda tipo, v, key: _otx(familia))
        ind_id = client.post("/indicators", json={"tipo": "ip", "valor": valor}).json()["id"]
        client.post(f"/indicators/{ind_id}/enrich")
        client.post(f"/indicators/{ind_id}/correlate")
        for _ in range(2):  # dos versiones del informe
            informe = client.post(f"/indicators/{ind_id}/report").json()
        for decision in ["aceptado", "rechazado"][:validaciones]:
            client.post(f"/reports/{informe['id']}/validate", json={"decision": decision})
        return ind_id

    return correr


def _cuenta(db, modelo, **filtro):
    return db.query(modelo).filter_by(**filtro).count()


def test_borra_en_cascada_todo_lo_del_indicador(client, db, pipeline):
    ind_id = pipeline("40.0.0.1", validaciones=2)
    tecnicas_antes = db.query(Technique).count()

    r = client.delete(f"/indicators/{ind_id}")
    assert r.status_code == 200
    assert r.json() == {
        "indicator_id": ind_id,
        "valor": "40.0.0.1",
        "eliminados": {
            "human_validation": 2, "reports": 2, "indicator_entity_link": 1, "enrichment_cache": 1,
            "indicators": 1, "entity_technique_link": 2, "entities": 1,
        },
    }
    assert db.get(Indicator, ind_id) is None
    for modelo in (EnrichmentCache, IndicatorEntityLink, Report):
        assert _cuenta(db, modelo, indicator_id=ind_id) == 0
    assert db.query(HumanValidation).count() == 0
    assert db.query(Entity).filter_by(nombre="emotet").count() == 0
    # El catálogo ATT&CK es compartido: nunca se borra.
    assert db.query(Technique).count() == tecnicas_antes
    # Y el recurso ya no existe para ningún endpoint.
    assert client.get(f"/indicators/{ind_id}").status_code == 404
    assert client.post(f"/indicators/{ind_id}/enrich").status_code == 404


def test_conserva_la_entidad_si_otro_indicador_la_usa(client, db, pipeline):
    borrado = pipeline("41.0.0.1")
    conservado = pipeline("41.0.0.2")
    entidad = db.query(Entity).filter_by(nombre="emotet").one()

    eliminados = client.delete(f"/indicators/{borrado}").json()["eliminados"]
    assert eliminados["entities"] == 0 and eliminados["entity_technique_link"] == 0
    assert db.get(Entity, entidad.id) is not None
    assert _cuenta(db, EntityTechniqueLink, entity_id=entidad.id) == 2
    # El otro indicador queda intacto, con su correlación e informes.
    cuerpo = client.get(f"/indicators/{conservado}").json()
    assert cuerpo["correlation"]["entity"]["nombre"] == "emotet" and len(cuerpo["reports"]) == 2


def test_indicador_solo_registrado(client, db):
    ind_id = client.post("/indicators", json={"tipo": "domain", "valor": "borrar-me.example"}).json()["id"]
    eliminados = client.delete(f"/indicators/{ind_id}").json()["eliminados"]
    assert eliminados["indicators"] == 1 and sum(eliminados.values()) == 1


def test_el_valor_se_puede_volver_a_registrar(client):
    ind_id = client.post("/indicators", json={"tipo": "ip", "valor": "42.0.0.1"}).json()["id"]
    assert client.post("/indicators", json={"tipo": "ip", "valor": "42.0.0.1"}).status_code == 409
    client.delete(f"/indicators/{ind_id}")
    r = client.post("/indicators", json={"tipo": "ip", "valor": "42.0.0.1"})
    assert r.status_code == 201 and r.json()["id"] != ind_id


def test_404_si_no_existe(client):
    r = client.delete("/indicators/999999")
    assert r.status_code == 404 and r.json() == {"detail": "Indicador no encontrado"}


def test_queda_constancia_en_el_log(client, caplog):
    import logging

    ind_id = client.post("/indicators", json={"tipo": "ip", "valor": "43.0.0.1"}).json()["id"]
    with caplog.at_level(logging.WARNING, logger="app.api.indicators"):
        client.delete(f"/indicators/{ind_id}")
    assert f"indicador #{ind_id} (43.0.0.1) eliminado en cascada" in caplog.text
