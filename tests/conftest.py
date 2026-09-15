import pytest
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.database import Base
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
    session = Session(bind=conn)
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        conn.close()
