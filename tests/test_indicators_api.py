"""POST /indicators — el único endpoint de negocio de la Etapa 3."""

import pytest

from app.db.repositories import indicator_repository


def _post(client, tipo, valor, **extra):
    return client.post("/indicators", json={"tipo": tipo, "valor": valor, **extra})


def test_crea_indicador_valido(client, db):
    r = _post(client, "ip", "8.8.4.4", fuente="manual")

    assert r.status_code == 201
    body = r.json()
    assert body["tipo"] == "ip" and body["valor"] == "8.8.4.4" and body["fuente"] == "manual"
    assert body["id"] is not None and body["timestamp_ingesta"] is not None

    # la fila existe de verdad en la base de test
    guardado = indicator_repository.get(db, body["id"])
    assert guardado is not None and guardado.valor == "8.8.4.4"


def test_fuente_es_opcional(client):
    r = _post(client, "domain", "ejemplo-sin-fuente.com")
    assert r.status_code == 201 and r.json()["fuente"] is None


def test_tipo_fuera_del_literal_es_422(client):
    r = _post(client, "email", "alguien@ejemplo.com")
    assert r.status_code == 422


@pytest.mark.parametrize(
    "tipo,valor",
    [
        ("ip", "no-es-una-ip"),
        ("domain", "-invalido.com"),
        ("hash", "abc123"),
        ("url", "ftp://ejemplo.com"),
    ],
)
def test_formato_invalido_por_tipo_es_422(client, tipo, valor):
    r = _post(client, tipo, valor)

    assert r.status_code == 422
    detalle = str(r.json()["detail"])
    assert valor in detalle and tipo in detalle


def test_valor_duplicado_es_409(client, db):
    assert _post(client, "ip", "1.1.1.1").status_code == 201

    r = _post(client, "ip", "1.1.1.1")
    assert r.status_code == 409
    assert r.json()["detail"] == "El indicador ya existe"

    # sigue habiendo una sola fila, y la sesión quedó usable tras el rollback
    assert len([i for i in indicator_repository.list(db) if i.valor == "1.1.1.1"]) == 1


def test_health_sigue_igual(client):
    assert client.get("/health").json() == {"status": "ok"}


# --- Etapa 4: normalización y deduplicación lógica ---


def test_url_se_persiste_canonica(client, db):
    r = _post(client, "url", "http://Example.COM/Path")

    assert r.status_code == 201
    assert r.json()["valor"] == "http://example.com/Path"
    assert indicator_repository.get(db, r.json()["id"]).valor == "http://example.com/Path"


def test_url_defangeada_equivalente_es_409(client):
    assert _post(client, "url", "http://Example.COM/Path").status_code == 201

    r = _post(client, "url", "hxxp://EXAMPLE[.]com/Path")
    assert r.status_code == 409
    assert r.json()["detail"] == "El indicador ya existe"


def test_dominio_defangeado_y_trailing_dot_colapsan(client, db):
    primero = _post(client, "domain", "EXAMPLE[.]COM")
    assert primero.status_code == 201
    assert primero.json()["valor"] == "example.com"

    assert _post(client, "domain", "example.com.").status_code == 409
    assert len([i for i in indicator_repository.list(db) if i.valor == "example.com"]) == 1


def test_ipv6_se_persiste_comprimida(client, db):
    r = _post(client, "ip", "2001:0DB8:0000:0000:0000:0000:0000:0001")

    assert r.status_code == 201
    assert r.json()["valor"] == "2001:db8::1"
    assert indicator_repository.get(db, r.json()["id"]).valor == "2001:db8::1"


def test_invalido_sigue_siendo_422_tras_normalizar(client):
    """La normalización no puede convertir un 422 en un 500."""
    for tipo, valor in [("ip", "no-es-una-ip"), ("url", "hxxp[:]//"), ("domain", "-mal.com")]:
        assert _post(client, tipo, valor).status_code == 422
