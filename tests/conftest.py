import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.api.correlation import get_attck_index
from app.core.config import settings
from app.correlation.attck_loader import AttckIndex
from app.db.database import Base, get_db
from app.main import app as fastapi_app
from app.db import models  # noqa: F401  — puebla Base.metadata con las 8 tablas


def _test_url() -> str:
    """Devuelve TEST_DATABASE_URL tras comprobar que no es la base de producción."""
    url = settings.TEST_DATABASE_URL
    if not url:
        pytest.skip("TEST_DATABASE_URL no configurada; levanta docker-compose.test.yml")

    host = make_url(url).host
    assert host in ("localhost", "127.0.0.1"), (
        f"TEST_DATABASE_URL apunta a '{host}', no a localhost. "
        "Los tests jamás deben tocar Supabase."
    )
    assert url != settings.DATABASE_URL, (
        "TEST_DATABASE_URL es idéntica a DATABASE_URL (la base de producción)."
    )
    return url


@pytest.fixture(scope="session")
def engine():
    eng = create_engine(_test_url())
    # create_all() es válido SOLO aquí: base efímera en Docker. Contra Supabase el
    # esquema lo gestiona Alembic y nada más.
    Base.metadata.create_all(eng)
    yield eng
    Base.metadata.drop_all(eng)
    eng.dispose()


@pytest.fixture
def db(engine):
    """Session limpia por test: transacción externa + rollback, sin recrear tablas."""
    conn = engine.connect()
    trans = conn.begin()
    # create_savepoint: el commit() del endpoint libera un SAVEPOINT en vez de cerrar la
    # transacción externa, así el rollback del teardown sigue deshaciéndolo todo.
    session = Session(bind=conn, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        conn.close()


@pytest.fixture
def attck_index() -> AttckIndex:
    """Índice ATT&CK sintético. Los tests nunca leen el bundle real de 50 MB."""
    return AttckIndex(
        techniques={
            "T9001": {"nombre": "Falsa Uno", "tactica": "Initial Access"},
            "T9002": {"nombre": "Falsa Dos", "tactica": "Execution"},
            "T9003": {"nombre": "Falsa Tres", "tactica": "Persistence"},
        },
        entity_type={"emotet": "malware", "apt-falso": "grupo", "ambigua": "grupo"},
        entity_aliases={"geodo": "emotet"},
        entity_techniques={
            "emotet": ["T9001", "T9002"],
            "apt-falso": ["T9003"],
            "ambigua": ["T9001", "T9003"],
        },
        ambiguous={"ambigua": ["grupo", "malware"]},
    )


@pytest.fixture
def client(db, attck_index):
    """TestClient con get_db y get_attck_index apuntando a los dobles de test.

    El lifespan no corre (TestClient no se usa como context manager), así que
    app.state.attck_index no existe: por eso se sobrescribe la dependencia.
    """
    fastapi_app.dependency_overrides[get_db] = lambda: db
    fastapi_app.dependency_overrides[get_attck_index] = lambda: attck_index
    yield TestClient(fastapi_app)
    fastapi_app.dependency_overrides.clear()
