"""Fase 7c: informe conjunto del lote, su análisis de IA y su validación con historial."""

import json

import pytest
from sqlalchemy import event

from app.ai_component.llm_client import LLMServiceError
from app.ai_component.prompt_builder import MAX_TECNICAS_LOTE, MAX_VINCULOS_CONTEXTO
from app.db.models import BatchValidation
from app.schemas.batch import MAX_INDICADORES_LOTE

OTX_MOCK = "app.enrichment.client.fetch_reputation"
LLM_MOCK = "app.ai_component.service.generate_analysis"
META = {"proveedor": "prueba", "modelo": "m", "latencia_ms": 1, "tokens": {}, "intentos_fallidos": []}
SECCIONES = ["## 1. Conclusión", "## 2. Indicadores", "## 3. Vínculos entre indicadores", "## 4. Cobertura ATT&CK conjunta",
             "## 5. Indicadores que no participan", "## 6. Cobertura de fuentes y límites", "## 7. Análisis"]


def _otx(familias=(), pulses=()):
    """Un pulse por id; todos con las mismas familias. Sin familias, solo etiquetas que no resuelven."""
    return {"pulse_info": {"count": len(pulses), "pulses": [
        {"id": pid, "name": "Nombre libre del autor del pulse", "indicator_count": 10, "tags": ["sin-entidad"],
         "malware_families": [{"display_name": f} for f in familias]}
        for pid in pulses
    ]}}


@pytest.fixture
def llm(vector_store, monkeypatch):
    """Texto oficial largo para T9001-T9003 y LLM simulado. `salida` se puede cambiar por test."""
    vector_store.documentos = {
        t: {"document": f"{t} (x)\n\n" + "Texto oficial de la técnica. " * 80, "metadata": {"nombre": t, "tactica": "x"}}
        for t in ("T9001", "T9002", "T9003")
    }
    estado = {"prompts": [], "salida": {"resumen": "Resumen del lote.", "hallazgos": [
        {"afirmacion": "I1 e I2 comparten un pulse.", "tipo": "evidencia", "fuentes": ["E-V1"]}]}}

    def _redactar(prompt, validar):
        estado["prompts"].append(prompt)
        return validar(json.dumps(estado["salida"])), META

    monkeypatch.setattr(LLM_MOCK, _redactar)
    return estado


def _lote(client, monkeypatch, casos, pasos=("enrich", "correlate")):
    """casos: [(tipo, valor, respuesta OTX)]. Registra el lote y corre los pasos en cada uno."""
    respuestas = {valor: otx for _, valor, otx in casos}
    monkeypatch.setattr(OTX_MOCK, lambda tipo, valor, key: respuestas[valor])
    r = client.post("/batches", json={"nombre": "Lote de prueba",
                                      "indicadores": [{"tipo": t, "valor": v} for t, v, _ in casos]})
    assert r.status_code == 201, r.text
    for item in r.json()["items"]:
        for paso in pasos:
            assert client.post(f"/indicators/{item['indicator_id']}/{paso}").status_code == 200
    return r.json()["batch"]["id"]


def _informe(client, lote_id):
    r = client.post(f"/batches/{lote_id}/report")
    assert r.status_code == 201, r.text
    return r.json()


# --- Contenido ---


def test_informe_con_relacion_demostrable(client, monkeypatch, llm):
    lote_id = _lote(client, monkeypatch, [
        ("ip", "90.0.0.1", _otx(["Emotet"], ["p-comun"])),
        ("ip", "90.0.0.2", _otx(["Emotet"], ["p-comun"])),
    ])
    informe = _informe(client, lote_id)

    assert informe["batch_id"] == lote_id and informe["conclusion"] == "relacion_demostrable"
    contenido = informe["contenido"]
    assert contenido.startswith(f"# Informe conjunto — lote #{lote_id}: Lote de prueba\n")
    assert [s for s in SECCIONES if s in contenido] == SECCIONES
    assert "Relación demostrable entre I1 y I2 (A1, confianza media)." in contenido
    assert "**Pulse compartido** (AlienVault OTX)" in contenido and "`p-comun`" in contenido
    # Los valores van como código: no se convierten en enlaces.
    assert "| I1 | `90.0.0.1` |" in contenido
    # Los metadatos congelan la misma correlación que GET muestra al vuelo.
    lote = client.get(f"/batches/{lote_id}").json()
    assert informe["metadatos"]["correlacion"] == lote["correlacion"]
    assert lote["informes"] == [informe]

    ia = informe["metadatos"]["ia"]
    assert ia["estado"] == "generado" and ia["seleccion"]["metodo"] == "solapamiento_y_tactica"
    [prompt] = llm["prompts"]
    assert all(f"[{b}]" in prompt for b in ("E-LOTE", "E-I1", "E-I2", "E-V1"))
    assert {b["id"] for b in ia["contexto"]} >= {"E-LOTE", "E-I1", "E-I2", "E-V1", "T9001"}
    # El nombre del pulse es texto libre de terceros: ni al prompt ni al informe.
    assert "Nombre libre del autor" not in prompt and "Nombre libre del autor" not in contenido
    assert "Resumen del lote." in contenido and "*Redactado por IA: prueba · m" in contenido


def test_sin_relacion_lo_declara_con_esas_palabras(client, monkeypatch, llm):
    lote_id = _lote(client, monkeypatch, [
        ("ip", "91.0.0.1", _otx(["Emotet"], ["p-a"])),
        ("ip", "91.0.0.2", _otx(["apt-falso"], ["p-b"])),
    ])
    informe = _informe(client, lote_id)

    assert informe["conclusion"] == "sin_relacion_demostrable"
    assert "> **Sin relación demostrable entre los indicadores.** Ningún par comparte" in informe["contenido"]
    assert "La ausencia de relación es un resultado válido, no un error del sistema." in informe["contenido"]
    assert "Ningún par de indicadores comparte evidencia." in informe["contenido"]
    # Aun sin relación hay algo que redactar (las entidades), así que el LLM sí se consulta.
    assert len(llm["prompts"]) == 1


def test_sin_ninguna_entidad_no_se_llama_al_llm(client, monkeypatch, vector_store):
    # Sin el fixture `llm`: el guard del conftest haría fallar el test si se llamara al modelo.
    lote_id = _lote(client, monkeypatch, [
        ("ip", "92.0.0.1", _otx([], ["p-1"])),
        ("ip", "92.0.0.2", _otx([], ["p-1"])),
    ])
    informe = _informe(client, lote_id)

    ia = informe["metadatos"]["ia"]
    assert ia["estado"] == "no_llamado"
    assert ia["motivo"] == "ningún indicador del lote resolvió entidad: por diseño no se consulta al modelo"
    assert vector_store.llamadas == []
    assert "Análisis narrativo no disponible" in informe["contenido"]
    assert "Menos de dos indicadores con entidad resuelta" in informe["contenido"]
    assert "| I1 | `92.0.0.1` | sin entidad atribuible" in informe["contenido"]


def test_si_el_llm_falla_el_informe_se_genera_igual(client, monkeypatch, llm):
    def _cae(prompt, validar):
        raise LLMServiceError("ningún proveedor de IA respondió: prueba", [{"proveedor": "p", "modelo": "m", "error": "x"}])

    monkeypatch.setattr(LLM_MOCK, _cae)
    lote_id = _lote(client, monkeypatch, [
        ("ip", "93.0.0.1", _otx(["Emotet"], ["p-comun"])),
        ("ip", "93.0.0.2", _otx(["Emotet"], ["p-comun"])),
    ])
    informe = _informe(client, lote_id)

    assert informe["metadatos"]["ia"]["estado"] == "fallido"
    assert "Análisis narrativo no disponible" in informe["contenido"]
    assert "> Motivo: ningún proveedor de IA respondió: prueba." in informe["contenido"]
    # Lo determinístico no depende del LLM.
    assert informe["conclusion"] == "relacion_demostrable"


def test_descarta_lo_que_cita_fuera_del_contexto(client, monkeypatch, llm):
    llm["salida"] = {"resumen": "Resumen.", "hallazgos": [
        {"afirmacion": "Vínculo válido.", "tipo": "evidencia", "fuentes": ["E-V1"]},
        {"afirmacion": "Vínculo inventado.", "tipo": "evidencia", "fuentes": ["E-V99"]},
        {"afirmacion": "Usan T9999.", "tipo": "inferencia", "fuentes": ["E-I1"]},
        {"afirmacion": "Evidencia sin fuente de evidencia.", "tipo": "evidencia", "fuentes": ["T9001"]},
    ]}
    lote_id = _lote(client, monkeypatch, [
        ("ip", "94.0.0.1", _otx(["Emotet"], ["p-comun"])),
        ("ip", "94.0.0.2", _otx(["Emotet"], ["p-comun"])),
    ])
    ia = _informe(client, lote_id)["metadatos"]["ia"]

    assert [h["afirmacion"] for h in ia["analisis"]["hallazgos"]] == ["Vínculo válido."]
    assert len(ia["descartes"]) == 3


def test_el_prompt_queda_acotado_con_20_indicadores(client, monkeypatch, llm):
    # El peor caso: 20 URL largas, todas en un pulse común (190 vínculos) y texto oficial largo.
    casos = [("url", f"http://h{n}.example/" + "a" * 300, _otx(["Emotet"], ["p-comun"])) for n in range(MAX_INDICADORES_LOTE)]
    informe = _informe(client, _lote(client, monkeypatch, casos))

    [prompt] = llm["prompts"]
    assert len(prompt) <= 16_000, len(prompt)
    assert f"(Se muestran {MAX_VINCULOS_CONTEXTO} de 190 vínculos, los de mayor confianza.)" in prompt
    contexto = informe["metadatos"]["ia"]["contexto"]
    assert sum(1 for b in contexto if b["id"].startswith("E-V")) == MAX_VINCULOS_CONTEXTO
    assert sum(1 for b in contexto if b["id"].startswith("E-I")) == MAX_INDICADORES_LOTE
    assert sum(1 for b in contexto if b["id"].startswith("T")) <= MAX_TECNICAS_LOTE
    assert all(len(b["texto"]) <= 501 for b in contexto if b["id"].startswith("T"))
    assert "a" * 301 not in prompt  # el valor de cada URL va recortado


def test_los_pendientes_no_impiden_el_informe(client, monkeypatch, vector_store):
    lote_id = _lote(client, monkeypatch, [("ip", "95.0.0.1", _otx(["Emotet"], ["p"])), ("ip", "95.0.0.2", _otx())],
                    pasos=())
    client.post(f"/indicators/{client.get(f'/batches/{lote_id}').json()['items'][0]['indicator_id']}/enrich")
    informe = _informe(client, lote_id)

    assert "**Cobertura:** parcial — pendientes: I1, I2" in informe["contenido"]
    assert "| I2 | `95.0.0.2` | sin enriquecer" in informe["contenido"]


# --- Errores y versiones ---


def test_sin_ningun_enriquecimiento_es_400_y_lote_inexistente_404(client, monkeypatch):
    lote_id = _lote(client, monkeypatch, [("ip", "96.0.0.1", _otx()), ("ip", "96.0.0.2", _otx())], pasos=())
    r = client.post(f"/batches/{lote_id}/report")
    assert r.status_code == 400 and "/enrich" in r.json()["detail"]
    assert client.post("/batches/999999/report").status_code == 404


def test_cada_informe_es_una_version_nueva(client, monkeypatch, vector_store):
    lote_id = _lote(client, monkeypatch, [("ip", "97.0.0.1", _otx()), ("ip", "97.0.0.2", _otx())])
    primero, segundo = _informe(client, lote_id), _informe(client, lote_id)
    assert [i["id"] for i in client.get(f"/batches/{lote_id}").json()["informes"]] == [primero["id"], segundo["id"]]


# --- Validación ---


def test_validacion_con_historial(client, db, monkeypatch, vector_store):
    lote_id = _lote(client, monkeypatch, [("ip", "98.0.0.1", _otx()), ("ip", "98.0.0.2", _otx())])
    informe = _informe(client, lote_id)

    decisiones = []
    for decision in ("aceptado", "rechazado"):
        r = client.post(f"/batch-reports/{informe['id']}/validate", json={"decision": decision})
        assert r.status_code == 201, r.text
        decisiones.append(r.json())
    assert [(v["batch_report_id"], v["decision"], v["analista"]) for v in decisiones] == [
        (informe["id"], "aceptado", None), (informe["id"], "rechazado", None)]
    assert db.query(BatchValidation).filter_by(batch_report_id=informe["id"]).count() == 2
    assert client.get(f"/batches/{lote_id}").json()["validaciones"] == decisiones

    [resumen] = [b for b in client.get("/batches").json() if b["id"] == lote_id]
    assert resumen["ultimo_informe"]["id"] == informe["id"]
    assert (resumen["ultimo_informe"]["conclusion"], resumen["decision"]) == ("sin_relacion_demostrable", "rechazado")

    # Un informe nuevo vuelve a quedar pendiente.
    _informe(client, lote_id)
    [resumen] = [b for b in client.get("/batches").json() if b["id"] == lote_id]
    assert resumen["decision"] is None


def test_validacion_404_y_422(client, monkeypatch, vector_store):
    r = client.post("/batch-reports/999999/validate", json={"decision": "aceptado"})
    assert r.status_code == 404 and r.json() == {"detail": "Informe del lote no encontrado"}

    lote_id = _lote(client, monkeypatch, [("ip", "99.0.0.1", _otx()), ("ip", "99.0.0.2", _otx())])
    informe = _informe(client, lote_id)
    assert client.post(f"/batch-reports/{informe['id']}/validate", json={"decision": "quizas"}).status_code == 422


# --- Consultas acotadas ---


def test_el_informe_ejecuta_las_mismas_sentencias_con_2_y_con_20(client, db, monkeypatch, vector_store):
    familias = ["Emotet", "apt-falso", "Ambigua"]

    def sentencias(n, base):
        lote_id = _lote(client, monkeypatch, [
            ("ip", f"{base}.0.0.{i}", _otx([familias[i % 3]], [f"p{i % 2}"])) for i in range(n)])
        db.expunge_all()
        cuenta = []
        escucha = lambda *a, **k: cuenta.append(1)  # noqa: E731
        event.listen(db.bind, "before_cursor_execute", escucha)
        try:
            _informe(client, lote_id)
        finally:
            event.remove(db.bind, "before_cursor_execute", escucha)
        return len(cuenta)

    dos, veinte = sentencias(2, 100), sentencias(MAX_INDICADORES_LOTE, 101)
    assert dos == veinte, f"{veinte} sentencias para 20 indicadores vs {dos} para 2"
