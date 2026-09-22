"""Etapa 9: errores no manejados sin filtrar detalles internos y CORS sin comodín."""

import logging

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.db.database import get_db
from app.main import app

# Credenciales y host inventados: si aparecen en la respuesta, hubo fuga.
BD_CAIDA = "postgresql+psycopg://usuario_secreto:clave_secreta@127.0.0.1:1/base_secreta"


@pytest.fixture
def client_bd_caida():
    """La base 'se apaga': cada sesión apunta a un puerto donde no escucha nadie."""
    engine = create_engine(BD_CAIDA, connect_args={"connect_timeout": 2})

    def _db():
        with Session(engine) as session:
            yield session

    app.dependency_overrides[get_db] = _db
    # Starlette re-lanza la excepción después de responder (para que el servidor la
    # loguee); sin raise_server_exceptions=False el test no vería la respuesta HTTP.
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()
    engine.dispose()


def test_error_no_manejado_es_500_generico(client_bd_caida, caplog):
    with caplog.at_level(logging.ERROR, logger="app.main"):
        r = client_bd_caida.post("/indicators", json={"tipo": "ip", "valor": "9.9.9.9"})

    assert r.status_code == 500
    assert r.json() == {"detail": "Error interno del servidor"}
    for fuga in ("traceback", "psycopg", "sqlalchemy", "operationalerror",
                 "127.0.0.1", "usuario_secreto", "clave_secreta", "base_secreta"):
        assert fuga not in r.text.lower()

    # El detalle completo sí queda del lado del servidor.
    [registro] = [x for x in caplog.records if x.name == "app.main"]
    assert "POST /indicators" in registro.getMessage() and registro.exc_info is not None


def test_errores_intencionales_no_se_interceptan(client):
    r = client.post("/indicators/999999/enrich")
    assert r.status_code == 404 and r.json() == {"detail": "Indicador no encontrado"}

    r = client.post("/indicators", json={"tipo": "ip", "valor": "no-es-una-ip"})
    assert r.status_code == 422 and isinstance(r.json()["detail"], list)


@pytest.mark.parametrize("origenes", ["*", "http://localhost:5173, *"])
def test_cors_rechaza_comodin(origenes):
    with pytest.raises(ValidationError, match="no admite"):
        Settings(DATABASE_URL="postgresql+psycopg://x@localhost/x", CORS_ORIGINS=origenes)


def test_cors_acepta_origenes_explicitos():
    s = Settings(DATABASE_URL="postgresql+psycopg://x@localhost/x",
                 CORS_ORIGINS="http://localhost:5173, https://nexo.example")
    assert s.cors_origins == ["http://localhost:5173", "https://nexo.example"]
