"""Fase 7a: lotes de indicadores. Ingesta en bloque con un resultado por ítem y consulta del
lote con un número de sentencias que no depende de cuántos indicadores tenga."""

import pytest
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError

from app.db.models import Batch, BatchItem
from app.schemas.batch import MAX_INDICADORES_LOTE

OTX_MOCK = "app.enrichment.client.fetch_reputation"


def _otx(familia):
    return {"pulse_info": {"count": 1, "pulses": [
        {"id": f"p-{familia}", "name": "p", "indicator_count": 10, "malware_families": [{"display_name": familia}], "tags": []}]}}


def _lote(client, *items, nombre=None):
    return client.post("/batches", json={"nombre": nombre, "indicadores": [{"tipo": t, "valor": v} for t, v in items]})


def _sentencias(db, accion) -> int:
    # En producción cada request trae una sesión nueva; aquí se comparte, así que se vacía el
    # identity map para medir como en producción (igual que test_consultas.py).
    db.expunge_all()
    sentencias = []
    escucha = lambda *a, **k: sentencias.append(1)  # noqa: E731
    event.listen(db.bind, "before_cursor_execute", escucha)
    try:
        accion()
    finally:
        event.remove(db.bind, "before_cursor_execute", escucha)
    return len(sentencias)


# --- POST /batches ---


def test_un_resultado_por_item_sin_abortar_el_lote(client):
    existente = client.post("/indicators", json={"tipo": "ip", "valor": "45.0.0.1"}).json()["id"]

    r = _lote(
        client,
        ("ip", "45.0.0.1"),
        ("domain", "lote-uno[.]example"),
        ("domain", "LOTE-UNO.EXAMPLE"),
        ("url", "HXXPS://LOTE-UNO[.]EXAMPLE/Ruta"),
        ("ip", "999.1.1.1"),
        (None, "no-es-un-ioc"),
        ("email", "a@b.example"),
        nombre="Triage de prueba",
    )
    assert r.status_code == 201, r.text
    cuerpo = r.json()
    lote_id = cuerpo["batch"]["id"]
    assert cuerpo["batch"]["nombre"] == "Triage de prueba"
    assert cuerpo["resumen"] == {"creados": 2, "existentes": 1, "duplicados": 1, "invalidos": 3}

    items = cuerpo["items"]
    assert [(i["posicion"], i["ingesta"], i["valor"]) for i in items] == [
        (1, "existente", "45.0.0.1"),
        (2, "creado", "lote-uno.example"),
        (3, "duplicado", None),
        (4, "creado", "https://lote-uno.example/Ruta"),  # refang sin distinguir mayúsculas; el path conserva las suyas
        (5, "invalido", None),
        (6, "invalido", None),
        (7, "invalido", None),
    ]
    # Lo existente se reutiliza con su id, sin 409.
    assert items[0]["indicator_id"] == existente
    assert items[2]["motivo"] == "mismo valor canónico que la posición 2" and items[2]["indicator_id"] is None
    assert "no tiene formato válido de tipo 'ip'" in items[4]["motivo"]
    assert items[5]["motivo"] == "tipo no reconocido"
    assert items[6]["motivo"] == "tipo 'email' no soportado (ip, domain, hash o url)"
    # La entrada se guarda tal como se pegó.
    assert [i["entrada"] for i in items][1:4] == ["lote-uno[.]example", "LOTE-UNO.EXAMPLE", "HXXPS://LOTE-UNO[.]EXAMPLE/Ruta"]

    # Los nuevos son indicadores normales, rastreables hasta su lote.
    [nuevo] = client.get("/indicators", params={"tipo": "domain", "valor": "lote-uno.example"}).json()
    assert nuevo["id"] == items[1]["indicator_id"] and nuevo["fuente"] == f"Lote #{lote_id}"
    assert client.get("/indicators", params={"tipo": "ip", "valor": "45.0.0.1"}).json()[0]["fuente"] is None


def test_si_ningun_item_es_valido_es_422_y_no_persiste_nada(client, db):
    antes = db.query(Batch).count(), db.query(BatchItem).count()
    r = _lote(client, ("ip", "999.1.1.1"), (None, "basura"))
    assert r.status_code == 422
    assert r.json()["detail"].startswith("Ningún indicador del lote es válido: 1: ")
    assert (db.query(Batch).count(), db.query(BatchItem).count()) == antes


@pytest.mark.parametrize("cuerpo", [
    {"indicadores": [{"tipo": "ip", "valor": "46.0.0.1"}]},  # un solo ítem no es un lote
    {"indicadores": [{"tipo": "ip", "valor": f"46.0.1.{n}"} for n in range(MAX_INDICADORES_LOTE + 1)]},
    {"indicadores": [{"tipo": "url", "valor": "http://a.example/" + "x" * 2048}, {"tipo": "ip", "valor": "46.0.0.2"}]},
    {"indicadores": [{"tipo": "x" * 17, "valor": "46.0.0.3"}, {"tipo": "ip", "valor": "46.0.0.4"}]},
    {"nombre": "n" * 201, "indicadores": [{"tipo": "ip", "valor": "46.0.0.5"}, {"tipo": "ip", "valor": "46.0.0.6"}]},
    {"indicadores": []},
], ids=["1-item", "21-items", "valor-largo", "tipo-largo", "nombre-largo", "vacio"])
def test_topes_de_la_peticion_son_422(client, cuerpo):
    assert client.post("/batches", json=cuerpo).status_code == 422


def test_reintenta_una_vez_si_otra_peticion_registra_el_mismo_valor(client, monkeypatch):
    from app.api import batches

    real, llamadas = batches.registrar_lote, []

    def con_carrera(db, nombre, filas):
        llamadas.append(1)
        if len(llamadas) == 1:
            raise IntegrityError("INSERT INTO indicators", {}, Exception("duplicate key"))
        return real(db, nombre, filas)

    monkeypatch.setattr(batches, "registrar_lote", con_carrera)
    r = _lote(client, ("ip", "47.0.0.1"), ("ip", "47.0.0.2"))
    assert r.status_code == 201 and len(llamadas) == 2
    assert r.json()["resumen"]["creados"] == 2


def test_dos_carreras_seguidas_son_409(client, monkeypatch):
    from app.api import batches

    def siempre(db, nombre, filas):
        raise IntegrityError("INSERT INTO indicators", {}, Exception("duplicate key"))

    monkeypatch.setattr(batches, "registrar_lote", siempre)
    r = _lote(client, ("ip", "47.1.0.1"), ("ip", "47.1.0.2"))
    assert r.status_code == 409 and "vuelve a intentarlo" in r.json()["detail"]


# --- GET /batches/{id} y GET /batches ---


def test_get_devuelve_los_items_y_la_investigacion_de_cada_miembro(client, monkeypatch):
    monkeypatch.setattr(OTX_MOCK, lambda tipo, valor, key: _otx("Emotet"))
    creado = _lote(client, ("ip", "48.0.0.1"), ("ip", "999.9.9.9"), ("ip", "48.0.0.2")).json()
    miembros = [i["indicator_id"] for i in creado["items"] if i["indicator_id"]]
    client.post(f"/indicators/{miembros[0]}/enrich")
    client.post(f"/indicators/{miembros[0]}/correlate")

    r = client.get(f"/batches/{creado['batch']['id']}")
    assert r.status_code == 200
    cuerpo = r.json()
    assert cuerpo["batch"] == creado["batch"]
    assert cuerpo["items"] == creado["items"]  # los descartes incluidos, en orden
    # Cada investigación es idéntica a GET /indicators/{id}, en el orden del lote.
    assert cuerpo["investigaciones"] == [client.get(f"/indicators/{i}").json() for i in miembros]
    assert cuerpo["investigaciones"][0]["correlation"]["entity"]["nombre"] == "emotet"
    assert cuerpo["investigaciones"][1]["enrichment"] is None


def test_lote_inexistente_es_404(client):
    r = client.get("/batches/999999")
    assert r.status_code == 404 and r.json() == {"detail": "Lote no encontrado"}


def test_lista_los_lotes_del_mas_reciente_al_mas_antiguo(client):
    primero = _lote(client, ("ip", "49.0.0.1"), ("ip", "49.0.0.2"), nombre="uno").json()["batch"]["id"]
    segundo = _lote(client, ("ip", "49.0.0.3"), ("ip", "49.0.0.3"), (None, "x"), nombre="dos").json()["batch"]["id"]

    lotes = client.get("/batches").json()
    assert [(b["id"], b["nombre"], b["indicadores"], b["descartados"]) for b in lotes[:2]] == [
        (segundo, "dos", 1, 2), (primero, "uno", 2, 0)]
    assert len(client.get("/batches", params={"limit": 1}).json()) == 1


# --- Consultas acotadas ---


def test_post_ejecuta_las_mismas_sentencias_con_2_y_con_20(client, db):
    def crear(n, base):
        return lambda: _lote(client, *[("ip", f"{base}.0.0.{i}") for i in range(n)])

    dos, veinte = _sentencias(db, crear(2, 60)), _sentencias(db, crear(MAX_INDICADORES_LOTE, 61))
    assert dos == veinte, f"{veinte} sentencias para 20 indicadores vs {dos} para 2"


def test_get_ejecuta_las_mismas_sentencias_con_2_y_con_20(client, db, monkeypatch):
    # Entidades distintas: con una sola, una carga perezosa por link pasaría desapercibida.
    familias = ["Emotet", "apt-falso", "Ambigua"]

    def lote_procesado(n, base):
        items = _lote(client, *[("ip", f"{base}.0.0.{i}") for i in range(n)]).json()["items"]
        for i, item in enumerate(items):
            monkeypatch.setattr(OTX_MOCK, lambda tipo, valor, key, f=familias[i % 3]: _otx(f))
            client.post(f"/indicators/{item['indicator_id']}/enrich")
            client.post(f"/indicators/{item['indicator_id']}/correlate")
        return client.get("/batches").json()[0]["id"]

    def consultar(lote_id):
        return lambda: client.get(f"/batches/{lote_id}").raise_for_status()

    dos = _sentencias(db, consultar(lote_procesado(2, 62)))
    veinte = _sentencias(db, consultar(lote_procesado(MAX_INDICADORES_LOTE, 63)))
    assert dos == veinte, f"{veinte} sentencias para 20 indicadores vs {dos} para 2"
