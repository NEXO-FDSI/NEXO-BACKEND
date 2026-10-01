"""GET /indicators y GET /indicators/{id}: consultas de solo lectura para reconstruir una
investigación desde otro navegador (antes, solo el localStorage de quien la creó)."""

import json

import pytest
from sqlalchemy import event

from app.db.repositories import indicator_repository
from app.db.repositories.enrichment_cache import enrichment_cache_repository
from app.enrichment.service import FUENTE

OTX_MOCK = "app.enrichment.client.fetch_reputation"


def _otx(*familias):
    return {"pulse_info": {"count": len(familias) or 0, "pulses": [
        {"name": "p", "indicator_count": 10, "malware_families": [{"display_name": f}], "tags": []}
        for f in familias
    ]}}


@pytest.fixture
def ia(vector_store, monkeypatch):
    """Vector store con texto para las técnicas sintéticas y LLM con salida JSON válida."""
    vector_store.documentos = {
        tid: {"document": f"{tid} (x)\n\nTexto oficial de {tid}.", "metadata": {"nombre": tid, "tactica": "x"}}
        for tid in ("T9001", "T9002", "T9003")
    }
    salida = {"resumen": "Emotet por su familia.",
              "hallazgos": [{"afirmacion": "Un pulse lo vincula.", "tipo": "evidencia", "fuentes": ["E-OTX"]}]}
    monkeypatch.setattr(
        "app.ai_component.service.generate_analysis",
        lambda prompt, validar: (validar(json.dumps(salida)), {
            "proveedor": "prueba", "modelo": "m", "latencia_ms": 1, "tokens": {}, "intentos_fallidos": []}),
    )


def _registrar(client, tipo, valor):
    r = client.post("/indicators", json={"tipo": tipo, "valor": valor})
    assert r.status_code == 201, r.text
    return r.json()["id"]


# --- GET /indicators ---


def test_busca_por_forma_canonica(client):
    ind_id = _registrar(client, "url", "http://evil-consulta.example/x")
    # Defangeado y con el host en mayúsculas: se normaliza igual que al registrar.
    r = client.get("/indicators", params={"tipo": "url", "valor": "hxxp://EVIL-CONSULTA[.]example/x"})
    assert r.status_code == 200 and [i["id"] for i in r.json()] == [ind_id]
    assert client.get("/indicators", params={"tipo": "url", "valor": "http://otro.example/x"}).json() == []


def test_valor_sin_tipo_es_422(client):
    r = client.get("/indicators", params={"valor": "8.8.8.8"})
    assert r.status_code == 422 and "tipo" in r.json()["detail"]


def test_lista_los_mas_recientes_primero(client):
    primero = _registrar(client, "ip", "31.0.0.1")
    segundo = _registrar(client, "ip", "31.0.0.2")
    ids = [i["id"] for i in client.get("/indicators", params={"limit": 2}).json()]
    assert ids == [segundo, primero]


# --- GET /indicators/{id} ---


def test_404_si_no_existe(client):
    assert client.get("/indicators/999999").status_code == 404


def test_recien_registrado_no_tiene_pasos(client):
    ind_id = _registrar(client, "ip", "32.0.0.1")
    cuerpo = client.get(f"/indicators/{ind_id}").json()
    assert cuerpo["indicator"]["valor"] == "32.0.0.1"
    assert cuerpo["enrichment"] is None and cuerpo["correlation"] is None
    assert cuerpo["reports"] == [] and cuerpo["validations"] == []


def test_reconstruye_lo_mismo_que_devolvieron_los_post(client, monkeypatch, ia):
    monkeypatch.setattr(OTX_MOCK, lambda tipo, valor, key: _otx("Emotet"))
    ind_id = _registrar(client, "ip", "33.0.0.1")
    enrich = client.post(f"/indicators/{ind_id}/enrich").json()
    corr = client.post(f"/indicators/{ind_id}/correlate").json()
    informe = client.post(f"/indicators/{ind_id}/report").json()
    validacion = client.post(f"/reports/{informe['id']}/validate",
                             json={"decision": "rechazado", "analista": "N2"}).json()

    cuerpo = client.get(f"/indicators/{ind_id}").json()
    assert cuerpo["correlation"] == corr
    assert cuerpo["reports"] == [informe]
    assert cuerpo["reports"][0]["metadatos"]["ia"]["estado"] == "generado"
    assert cuerpo["validations"] == [validacion]
    # Mismo enriquecimiento; solo cambia que ahora sale de la caché.
    assert cuerpo["enrichment"]["detalle"] == enrich["detalle"]
    assert [f["estado"] for f in cuerpo["enrichment"]["fuentes"]] == [f["estado"] for f in enrich["fuentes"]]
    assert cuerpo["enrichment"]["fuentes"][0]["desde_cache"] is True


def test_sin_entidad_la_correlacion_es_sin_asociacion_aunque_no_se_haya_pedido(client, db):
    """Determinística sobre la caché: /correlate daría exactamente esto."""
    ind = indicator_repository.create(db, {"tipo": "ip", "valor": "34.0.0.1"})
    enrichment_cache_repository.create(db, {"indicator_id": ind.id, "fuente_api": FUENTE,
                                            "respuesta_json": json.dumps(_otx())})
    corr = client.get(f"/indicators/{ind.id}").json()["correlation"]
    assert corr == {"indicator_id": ind.id, "resuelto": False, "entity": None, "confianza": None,
                    "evidencia": None, "tecnicas": []}


def test_con_entidad_pero_sin_correlate_la_correlacion_no_se_inventa(client, db):
    ind = indicator_repository.create(db, {"tipo": "ip", "valor": "35.0.0.1"})
    enrichment_cache_repository.create(db, {"indicator_id": ind.id, "fuente_api": FUENTE,
                                            "respuesta_json": json.dumps(_otx("Emotet"))})
    assert client.get(f"/indicators/{ind.id}").json()["correlation"] is None


def test_ip_no_publica_se_reconstruye_omitida(client):
    ind_id = _registrar(client, "ip", "10.9.9.9")
    cuerpo = client.get(f"/indicators/{ind_id}").json()
    # OTX omitida; ThreatFox y VT, "no configuradas" en tests. Ninguna se consultó.
    estados = {f["fuente"]: f["estado"] for f in cuerpo["enrichment"]["fuentes"]}
    assert estados[FUENTE] == "omitido" and set(estados.values()) <= {"omitido", "no_configurado"}
    assert cuerpo["correlation"]["resuelto"] is False


def test_get_no_escribe_nada(client, db, monkeypatch, ia):
    monkeypatch.setattr(OTX_MOCK, lambda tipo, valor, key: _otx("Emotet"))
    ind_id = _registrar(client, "ip", "36.0.0.1")
    client.post(f"/indicators/{ind_id}/enrich")
    client.post(f"/indicators/{ind_id}/report")

    sentencias = []
    escucha = lambda conn, cursor, sql, *a, **k: sentencias.append(sql.split()[0].upper())  # noqa: E731
    event.listen(db.bind, "before_cursor_execute", escucha)
    try:
        assert client.get(f"/indicators/{ind_id}").status_code == 200
        assert client.get("/indicators", params={"tipo": "ip", "valor": "36.0.0.1"}).status_code == 200
    finally:
        event.remove(db.bind, "before_cursor_execute", escucha)
    assert sentencias and set(sentencias) <= {"SELECT", "SAVEPOINT", "RELEASE", "ROLLBACK"}, sentencias
