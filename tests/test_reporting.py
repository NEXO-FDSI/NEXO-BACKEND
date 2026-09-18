"""Etapa 7: informe con plantilla fija + validación humana. Usa el AttckIndex del conftest."""

import json

from app.db.repositories import human_validation_repository, indicator_repository, report_repository
from app.db.repositories.enrichment_cache import enrichment_cache_repository
from app.enrichment.service import FUENTE
from app.reporting.template import build_report_content, nivel_confianza


def _detalle(*, familias=(), count=1):
    return {"pulse_info": {"count": count, "pulses": [{
        "name": "x", "malware_families": [{"display_name": f} for f in familias], "tags": []}]}}


def _indicador(db, valor="10.0.0.1"):
    return indicator_repository.create(db, {"tipo": "ip", "valor": valor})


def _cachear(db, indicator, detalle):
    return enrichment_cache_repository.create(db, {
        "indicator_id": indicator.id, "fuente_api": FUENTE, "respuesta_json": json.dumps(detalle)})


RESUELTO = {
    "resuelto": True,
    "entity": {"id": 1, "nombre": "emotet", "tipo": "malware"},
    "confianza": 0.9,
    "evidencia": "pulse_info.pulses[].malware_families[].display_name = 'Emotet'",
    "tecnicas": [
        {"id": "T9001", "nombre": "Falsa Uno", "tactica": "Initial Access"},
        {"id": "T9002", "nombre": "Falsa Dos", "tactica": "Execution"},
    ],
}
SIN_EVIDENCIA = {"resuelto": False, "entity": None, "confianza": None, "evidencia": None, "tecnicas": []}


# --- plantilla ---


def test_plantilla_resuelto(db):
    md = build_report_content(_indicador(db), _detalle(familias=["Emotet"]), RESUELTO)
    assert md.startswith("# Informe de indicador: 10.0.0.1\n")
    assert "**Tipo:** ip" in md and "**Nivel de confianza:** 0.9" in md
    assert "- Evidencia encontrada: Sí" in md
    assert "- Reportes (pulses) que mencionan este indicador: 1" in md
    assert "- **Entidad asociada:** emotet (malware)" in md
    assert "| T9001 | Falsa Uno | Initial Access |" in md
    assert "| T9002 | Falsa Dos | Execution |" in md
    assert "**Fuente de las técnicas:** MITRE ATT&CK" in md
    assert md.endswith("## Estado de validación\n\nPendiente de revisión humana.\n")


def test_plantilla_sin_evidencia(db):
    md = build_report_content(_indicador(db), {"pulse_info": {"count": 0, "pulses": []}}, SIN_EVIDENCIA)
    assert "Sin evidencia suficiente" in md
    assert "### Técnicas documentadas" not in md
    assert "- Evidencia encontrada: No" in md
    assert "**Nivel de confianza:** 0.0" in md
    assert "Pendiente de revisión humana." in md


def test_plantilla_sin_pulse_info(db):
    md = build_report_content(_indicador(db), {}, SIN_EVIDENCIA)
    assert "- Reportes (pulses) que mencionan este indicador: 0" in md


def test_nivel_confianza():
    assert nivel_confianza(RESUELTO) == 0.9
    assert nivel_confianza(SIN_EVIDENCIA) == 0.0


# --- flujo completo indicador → informe → validación ---


def test_flujo_completo(client, db):
    r = client.post("/indicators", json={"tipo": "ip", "valor": "20.0.0.1"})
    assert r.status_code == 201
    ind_id = r.json()["id"]
    _cachear(db, indicator_repository.get(db, ind_id), _detalle(familias=["Emotet"]))

    r = client.post(f"/indicators/{ind_id}/report")
    assert r.status_code == 201, r.text
    informe = r.json()
    assert informe["indicator_id"] == ind_id and informe["nivel_confianza"] == 0.9
    assert "emotet" in informe["contenido"] and "T9001" in informe["contenido"]

    r = client.post(f"/reports/{informe['id']}/validate",
                    json={"decision": "aceptado", "analista": "analista de prueba"})
    assert r.status_code == 201, r.text
    assert r.json()["report_id"] == informe["id"] and r.json()["decision"] == "aceptado"

    # verificación directa en la base de test
    fila = report_repository.get(db, informe["id"])
    assert fila is not None and fila.contenido == informe["contenido"]
    validaciones = [v for v in human_validation_repository.list(db) if v.report_id == informe["id"]]
    assert len(validaciones) == 1
    assert validaciones[0].decision == "aceptado" and validaciones[0].analista == "analista de prueba"


def test_informe_sin_evidencia_tiene_confianza_cero(client, db):
    ind = _indicador(db, "20.0.0.2")
    _cachear(db, ind, {"pulse_info": {"count": 0, "pulses": []}})
    r = client.post(f"/indicators/{ind.id}/report")
    assert r.status_code == 201
    assert r.json()["nivel_confianza"] == 0.0 and "Sin evidencia suficiente" in r.json()["contenido"]


def test_report_400_sin_enriquecimiento(client, db):
    ind = _indicador(db, "20.0.0.3")
    r = client.post(f"/indicators/{ind.id}/report")
    assert r.status_code == 400 and "/enrich" in r.json()["detail"]


def test_report_404_indicador_inexistente(client):
    assert client.post("/indicators/999999/report").status_code == 404


def test_validate_404_informe_inexistente(client):
    r = client.post("/reports/999999/validate", json={"decision": "aceptado"})
    assert r.status_code == 404


def test_validate_422_decision_invalida(client, db):
    ind = _indicador(db, "20.0.0.4")
    _cachear(db, ind, _detalle())
    report_id = client.post(f"/indicators/{ind.id}/report").json()["id"]
    r = client.post(f"/reports/{report_id}/validate", json={"decision": "quizas"})
    assert r.status_code == 422


def test_validate_permite_multiples_validaciones(client, db):
    ind = _indicador(db, "20.0.0.5")
    _cachear(db, ind, _detalle())
    report_id = client.post(f"/indicators/{ind.id}/report").json()["id"]
    for decision in ("rechazado", "aceptado"):
        assert client.post(f"/reports/{report_id}/validate", json={"decision": decision}).status_code == 201
    assert len([v for v in human_validation_repository.list(db) if v.report_id == report_id]) == 2
