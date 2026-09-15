"""CRUD genérico sobre las 8 entidades: create / get / list.

Cada caso construye su payload con el schema *Create y lo pasa con model_dump(),
así cada test ejercita schema y repositorio a la vez. Las entidades hijas crean
sus padres primero, por eso las factories reciben la Session.
"""

import itertools

import pytest

from app.db.repositories import (
    enrichment_cache_repository,
    entity_repository,
    entity_technique_link_repository,
    human_validation_repository,
    indicator_entity_link_repository,
    indicator_repository,
    report_repository,
    technique_repository,
)
from app.schemas import (
    EnrichmentCacheCreate,
    EntityCreate,
    EntityTechniqueLinkCreate,
    HumanValidationCreate,
    IndicatorCreate,
    IndicatorEntityLinkCreate,
    ReportCreate,
    TechniqueCreate,
)

_counter = itertools.count()


def _uniq(prefix: str = "") -> str:
    """Valor único: indicators.valor y techniques.id tienen PK/índice único."""
    return f"{prefix}{next(_counter)}"


# --- factories: cada una devuelve un schema *Create, creando padres si hace falta ---

def _indicator(db):
    return IndicatorCreate(tipo="ip", valor=f"10.0.0.{_uniq()}", fuente="test")


def _entity(db):
    return EntityCreate(nombre=f"APT{_uniq()}", tipo="grupo")


def _technique(db):
    return TechniqueCreate(id=f"T{_uniq('9')}", nombre="Phishing", tactica="initial-access")


def _enrichment_cache(db):
    ind = indicator_repository.create(db, _indicator(db).model_dump())
    return EnrichmentCacheCreate(
        indicator_id=ind.id, fuente_api="virustotal", respuesta_json='{"malicious": 3}'
    )


def _indicator_entity_link(db):
    ind = indicator_repository.create(db, _indicator(db).model_dump())
    ent = entity_repository.create(db, _entity(db).model_dump())
    return IndicatorEntityLinkCreate(
        indicator_id=ind.id, entity_id=ent.id, evidencia="pasiva DNS", confianza=0.87
    )


def _entity_technique_link(db):
    ent = entity_repository.create(db, _entity(db).model_dump())
    tec = technique_repository.create(db, _technique(db).model_dump())
    return EntityTechniqueLinkCreate(
        entity_id=ent.id, technique_id=tec.id, fuente_attck="enterprise-attack"
    )


def _report(db):
    ind = indicator_repository.create(db, _indicator(db).model_dump())
    return ReportCreate(indicator_id=ind.id, contenido="informe de prueba", nivel_confianza=0.75)


def _human_validation(db):
    rep = report_repository.create(db, _report(db).model_dump())
    return HumanValidationCreate(report_id=rep.id, decision="aceptado", analista="analista1")


CASES = [
    ("indicator", indicator_repository, _indicator),
    ("enrichment_cache", enrichment_cache_repository, _enrichment_cache),
    ("entity", entity_repository, _entity),
    ("indicator_entity_link", indicator_entity_link_repository, _indicator_entity_link),
    ("technique", technique_repository, _technique),
    ("entity_technique_link", entity_technique_link_repository, _entity_technique_link),
    ("report", report_repository, _report),
    ("human_validation", human_validation_repository, _human_validation),
]

params = pytest.mark.parametrize(
    "repo,factory", [(r, f) for _, r, f in CASES], ids=[n for n, _, _ in CASES]
)


@params
def test_create(db, repo, factory):
    payload = factory(db).model_dump()
    obj = repo.create(db, payload)

    assert repo._pk.name in {c.name for c in repo.model.__table__.columns}
    assert getattr(obj, "id") is not None
    for field, value in payload.items():
        assert getattr(obj, field) == value


@params
def test_get(db, repo, factory):
    obj = repo.create(db, factory(db).model_dump())

    assert repo.get(db, obj.id) is obj
    missing = "T-no-existe" if isinstance(obj.id, str) else 10**9
    assert repo.get(db, missing) is None


@params
def test_list(db, repo, factory):
    first = repo.create(db, factory(db).model_dump())
    second = repo.create(db, factory(db).model_dump())

    ids = [o.id for o in repo.list(db)]
    assert first.id in ids and second.id in ids
    assert len(repo.list(db, limit=1)) == 1
    assert repo.list(db, skip=1, limit=1)[0].id != repo.list(db, limit=1)[0].id
