"""GET /indicators y GET /indicators/{id}: consultas de solo lectura para reconstruir una
investigación desde otro navegador (antes, solo el localStorage de quien la creó)."""

import json

import pytest
from sqlalchemy import event

from app.db.repositories import indicator_repository
from app.db.repositories.enrichment_cache import enrichment_cache_repository, get_by_indicator_and_source
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
                             json={"decision": "rechazado"}).json()

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
                    "evidencia": None, "fuentes": [], "tecnicas": []}


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


# --- GET /investigations (paginado) ---


def test_pagina_de_a_10_del_mas_reciente_al_mas_antiguo(client):
    ids = [_registrar(client, "ip", f"50.0.0.{n}") for n in range(12)]
    r = client.get("/investigations")
    assert r.status_code == 200
    cuerpo = r.json()
    assert (cuerpo["page"], cuerpo["size"], cuerpo["total"], cuerpo["pages"]) == (1, 10, 12, 2)
    assert [i["indicator"]["id"] for i in cuerpo["items"]] == ids[::-1][:10]

    segunda = client.get("/investigations", params={"page": 2}).json()
    assert [i["indicator"]["id"] for i in segunda["items"]] == ids[1::-1]
    assert client.get("/investigations", params={"page": 3}).json()["items"] == []


@pytest.mark.parametrize("params", [{"size": 11}, {"size": 0}, {"page": 0}])
def test_limites_de_paginacion_son_422(client, params):
    assert client.get("/investigations", params=params).status_code == 422


def test_cada_item_es_la_investigacion_con_otx_recortado(client, db, monkeypatch, ia):
    crudo = _otx("Emotet")
    crudo["pulse_info"]["pulses"][0]["description"] = "texto largo que no viaja en el listado"
    crudo["sections"] = ["general", "geo"]
    monkeypatch.setattr(OTX_MOCK, lambda tipo, valor, key: crudo)
    ind_id = _registrar(client, "ip", "51.0.0.1")
    client.post(f"/indicators/{ind_id}/enrich")
    client.post(f"/indicators/{ind_id}/report")

    [item] = client.get("/investigations").json()["items"]
    completo = client.get(f"/indicators/{ind_id}").json()
    # Ni el listado ni la investigación exponen la respuesta cruda de OTX...
    assert "detalle_completo" not in item["enrichment"]
    assert "sections" not in item["enrichment"]["detalle"]
    assert "description" not in item["enrichment"]["detalle"]["pulse_info"]["pulses"][0]
    assert item["enrichment"]["detalle"]["pulse_info"]["pulses"][0]["malware_families"] == [{"display_name": "Emotet"}]
    # ...que sigue completa en la BD, por trazabilidad.
    assert json.loads(get_by_indicator_and_source(db, ind_id, FUENTE).respuesta_json) == crudo
    # La investigación es idéntica al ítem del listado.
    assert item == completo


def test_consultas_constantes_sin_importar_el_tamano_de_la_pagina(client, db, monkeypatch, ia):
    # Entidades distintas: con una sola, una carga perezosa por link pasaría desapercibida.
    familias = ["Emotet", "apt-falso", "Ambigua"]
    for n in range(10):
        monkeypatch.setattr(OTX_MOCK, lambda tipo, valor, key, f=familias[n % 3]: _otx(f))
        ind_id = _registrar(client, "ip", f"52.0.0.{n}")
        client.post(f"/indicators/{ind_id}/enrich")
        client.post(f"/indicators/{ind_id}/report")

    def consultas(size):
        # En producción cada request trae una sesión nueva; aquí se comparte, así que se vacía
        # el identity map para medir como en producción.
        db.expunge_all()
        sentencias = []
        escucha = lambda *a, **k: sentencias.append(1)  # noqa: E731
        event.listen(db.bind, "before_cursor_execute", escucha)
        try:
            assert len(client.get("/investigations", params={"size": size}).json()["items"]) == size
        finally:
            event.remove(db.bind, "before_cursor_execute", escucha)
        return len(sentencias)

    una, diez = consultas(1), consultas(10)
    assert diez == una, f"{diez} consultas para 10 investigaciones vs {una} para 1"
