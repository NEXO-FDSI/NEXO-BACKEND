import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.api.correlation import get_attck_index
from app.api.indicators import get_vector_store
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


class FakeVectorStore:
    """Doble del vector store. Registra las llamadas para poder afirmar que NO ocurrieron."""

    def __init__(self, documentos: dict[str, dict] | None = None):
        self.documentos = documentos or {}
        self.llamadas: list[list[str]] = []

    def upsert(self, *args, **kwargs):
        raise AssertionError("los tests no siembran embeddings")

    def get_by_ids(self, ids: list[str]) -> dict[str, dict]:
        self.llamadas.append(ids)
        return {i: self.documentos[i] for i in ids if i in self.documentos}


@pytest.fixture
def vector_store() -> FakeVectorStore:
    """Vacío por defecto: así ningún test dispara el LLM sin pedirlo explícitamente."""
    return FakeVectorStore()


@pytest.fixture(autouse=True)
def sin_llm_real(monkeypatch):
    """Garantía estructural de que ninguna prueba llegue a Ollama.

    Los tests que sí necesitan una respuesta vuelven a parchear generate_analysis.
    """
    def _prohibido(prompt: str) -> str:
        raise AssertionError("un test intentó llamar al LLM real")

    monkeypatch.setattr("app.ai_component.service.generate_analysis", _prohibido)


@pytest.fixture
def client(db, attck_index, vector_store):
    """TestClient con get_db, get_attck_index y get_vector_store apuntando a los dobles.

    El lifespan no corre (TestClient no se usa como context manager), así que
    app.state.attck_index no existe: por eso se sobrescriben las dependencias.
    """
    fastapi_app.dependency_overrides[get_db] = lambda: db
    fastapi_app.dependency_overrides[get_attck_index] = lambda: attck_index
    fastapi_app.dependency_overrides[get_vector_store] = lambda: vector_store
    yield TestClient(fastapi_app)
    fastapi_app.dependency_overrides.clear()
