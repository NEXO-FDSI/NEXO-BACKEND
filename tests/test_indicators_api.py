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
