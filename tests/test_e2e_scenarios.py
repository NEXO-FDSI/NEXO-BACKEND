"""Etapa 9: los 6 escenarios oficiales de la propuesta (sección 5.1), de punta a punta.

Ingesta → enrich → correlate → report (→ validate) por HTTP, contra el Postgres de Docker.
Sin red: OTX sale de respuestas reales congeladas en data/test_dataset/scenarios.json, el
índice ATT&CK es un subconjunto real congelado (attck_subset.json) y el LLM va mockeado.
"""

import json
from pathlib import Path

import pytest

from app.core.config import settings
from app.correlation.attck_loader import AttckIndex, load_attck_index
from app.correlation.service import resolve_entity_from_enrichment
from app.db.repositories import human_validation_repository, report_repository

DATASET = Path(__file__).resolve().parents[1] / "data" / "test_dataset"
ESCENARIOS = json.loads((DATASET / "scenarios.json").read_text(encoding="utf-8"))
SUBSET = json.loads((DATASET / "attck_subset.json").read_text(encoding="utf-8"))
ANALISIS = "Análisis redactado por el LLM mockeado."


@pytest.fixture
def attck_index() -> AttckIndex:
    """Sobrescribe el índice sintético del conftest: el client lo inyecta por nombre."""
    return AttckIndex(**SUBSET)


@pytest.fixture
def ia(vector_store, monkeypatch) -> list[str]:
    """Vector store con texto para todas las técnicas y LLM mockeado. Devuelve los prompts."""
    vector_store.documentos = {
        tid: {"document": f"{d['nombre']} ({d['tactica']})\n\nDescripción congelada de {tid}.",
              "metadata": d}
        for tid, d in SUBSET["techniques"].items()
    }
    prompts = []

    def _redactar(prompt: str, validar) -> tuple:
        prompts.append(prompt)
        # Pasa por el validador real: el e2e también ejercita el parseo del JSON.
        return validar(json.dumps({"resumen": ANALISIS})), {
            "proveedor": "prueba", "modelo": "congelado", "latencia_ms": 1,
            "tokens": {}, "intentos_fallidos": []}

    monkeypatch.setattr("app.ai_component.service.generate_analysis", _redactar)
    return prompts


def _pipeline(client, monkeypatch, casos: list[dict]) -> list[dict]:
    """Corre el pipeline completo para cada caso; OTX devuelve la respuesta congelada."""
    respuestas = {c["indicator"]["valor"]: c["enrichment_response"] for c in casos}
    consultas = []

    def _otx_congelado(tipo: str, valor: str, api_key: str) -> dict:
        consultas.append(valor)
        return respuestas[valor]

    monkeypatch.setattr("app.enrichment.client.fetch_reputation", _otx_congelado)

    resultados = []
    for caso in casos:
        r = client.post("/indicators", json=caso["indicator"])
        assert r.status_code == 201, r.text
        ind_id = r.json()["id"]

        pasos = {}
        for paso, codigo in (("enrich", 200), ("correlate", 200), ("report", 201)):
            r = client.post(f"/indicators/{ind_id}/{paso}")
            assert r.status_code == codigo, f"{paso}: {r.text}"
            pasos[paso] = r.json()
        resultados.append(pasos)

    # Una sola consulta a OTX por indicador: correlate y report leen de enrichment_cache.
    assert sorted(consultas) == sorted(respuestas)
    return resultados


def _tecnicas(resultado: dict) -> set[str]:
    return {t["id"] for t in resultado["correlate"]["tecnicas"]}


def _assert_sin_asociacion(resultado: dict, vector_store):
    corr, informe = resultado["correlate"], resultado["report"]
    assert corr["resuelto"] is False and corr["entity"] is None and corr["tecnicas"] == []
    assert informe["nivel_confianza"] == 0.0
    assert "Sin evidencia suficiente" in informe["contenido"]
    assert "### Técnicas documentadas" not in informe["contenido"]
    # Sin entidad no hay nada que redactar: ni vector store ni LLM (el guard del conftest
    # hace fallar el test si se llamara).
    assert vector_store.llamadas == []


def test_escenario_1_amenaza_conocida(client, monkeypatch, ia):
    esc = ESCENARIOS["scenario_1_amenaza_conocida"]
    esperado = esc["expected"]
    [r] = _pipeline(client, monkeypatch, [esc])

    assert r["enrich"]["tiene_evidencia"] is True
    corr = r["correlate"]
    assert corr["resuelto"] is True
    assert corr["entity"]["nombre"] == esperado["entidad"]
    assert corr["confianza"] >= esperado["min_confianza"]
    assert len(corr["tecnicas"]) >= esperado["min_tecnicas"]

    contenido = r["report"]["contenido"]
    assert r["report"]["nivel_confianza"] == corr["confianza"]
    assert f"**Entidad asociada:** {esperado['entidad']}" in contenido
    assert "### Técnicas documentadas" in contenido
    assert all(f"| {tid} |" in contenido for tid in _tecnicas(r))
    assert f"## Análisis\n\n{ANALISIS}" in contenido
    assert len(ia) == 1 and esperado["entidad"] in ia[0]


def test_escenario_2_informacion_incompleta(client, monkeypatch, vector_store):
    esc = ESCENARIOS["scenario_2_informacion_incompleta"]
    [r] = _pipeline(client, monkeypatch, [esc])

    assert r["enrich"]["tiene_evidencia"] is esc["expected"]["tiene_evidencia"]
    _assert_sin_asociacion(r, vector_store)
    assert "Análisis narrativo no disponible" in r["report"]["contenido"]


def test_escenario_3_multiples_tecnicas(client, monkeypatch, ia):
    esc = ESCENARIOS["scenario_3_multiples_tecnicas"]
    resultados = _pipeline(client, monkeypatch, esc["indicators"])

    for caso, r in zip(esc["indicators"], resultados):
        assert r["correlate"]["resuelto"] is True, caso["rol"]
        assert r["correlate"]["entity"]["nombre"] == caso["expected"]["entidad"], caso["rol"]
        assert "### Técnicas documentadas" in r["report"]["contenido"]

    # Cada indicador aporta un conjunto de técnicas propio...
    assert len({r["correlate"]["entity"]["nombre"] for r in resultados}) == len(resultados)
    assert len({frozenset(_tecnicas(r)) for r in resultados}) == len(resultados)
    # ...y en conjunto cubren varias fases de la cadena de ataque.
    tacticas = {t["tactica"] for r in resultados for t in r["correlate"]["tecnicas"]}
    assert len(tacticas) >= esc["expected"]["min_tacticas"]
    assert len(ia) == len(resultados)


def test_escenario_4_misma_campana(client, monkeypatch, ia):
    esc = ESCENARIOS["scenario_4_misma_campana"]
    resultados = _pipeline(client, monkeypatch, esc["indicators"])

    assert all(r["correlate"]["resuelto"] is True for r in resultados)
    assert {r["correlate"]["entity"]["nombre"] for r in resultados} == {esc["expected"]["entidad"]}
    # Misma entidad => misma fila en entities y técnicas comunes a todos los indicadores.
    assert len({r["correlate"]["entity"]["id"] for r in resultados}) == 1
    assert set.intersection(*(_tecnicas(r) for r in resultados))


def test_escenario_5_indicador_benigno(client, monkeypatch, vector_store):
    esc = ESCENARIOS["scenario_5_indicador_benigno"]
    [r] = _pipeline(client, monkeypatch, [esc])

    assert r["enrich"]["tiene_evidencia"] is esc["expected"]["tiene_evidencia"]
    _assert_sin_asociacion(r, vector_store)


def test_escenario_6_asociacion_incorrecta(client, monkeypatch, db, ia):
    esc = ESCENARIOS["scenario_6_asociacion_incorrecta"]
    esperado = esc["expected"]
    [r] = _pipeline(client, monkeypatch, [esc])

    # El sistema propone una hipótesis de baja confianza que no es la entidad real...
    corr = r["correlate"]
    assert corr["resuelto"] is True
    assert corr["entity"]["nombre"] == esperado["entidad_propuesta"] != esperado["entidad_real"]
    assert corr["confianza"] <= esperado["max_confianza"]
    assert r["report"]["nivel_confianza"] <= esperado["max_confianza"]

    # ...y la validación humana la rechaza, dejando la corrección registrada.
    informe = r["report"]
    v = client.post(f"/reports/{informe['id']}/validate",
                    json={"decision": esperado["validation_decision"]})
    assert v.status_code == 201, v.text
    assert v.json()["report_id"] == informe["id"] and v.json()["decision"] == "rechazado"

    filas = [f for f in human_validation_repository.list(db) if f.report_id == informe["id"]]
    assert len(filas) == 1
    assert filas[0].decision == "rechazado" and filas[0].analista is None  # sin login aún
    # El informe rechazado no se borra: queda para auditoría junto con su rechazo.
    assert report_repository.get(db, informe["id"]).contenido == informe["contenido"]


def _todas_las_respuestas() -> list[dict]:
    return [c["enrichment_response"]
            for esc in ESCENARIOS.values() for c in esc.get("indicators", [esc])]


@pytest.mark.skipif(not Path(settings.ATTCK_STIX_PATH).exists(),
                    reason="bundle STIX real no disponible (está en .gitignore)")
def test_subset_equivale_al_bundle_real(attck_index):
    """Si alguien edita scenarios.json sin regenerar attck_subset.json, esto lo detecta."""
    completo = load_attck_index(settings.ATTCK_STIX_PATH)
    for respuesta in _todas_las_respuestas():
        esperado = resolve_entity_from_enrichment(respuesta, completo)
        assert resolve_entity_from_enrichment(respuesta, attck_index) == esperado
        if esperado is not None:
            nombre = esperado["nombre_canonico"]
            assert attck_index.entity_techniques[nombre] == completo.entity_techniques[nombre]
            for tid in completo.entity_techniques[nombre]:
                assert attck_index.techniques[tid] == completo.techniques[tid]
