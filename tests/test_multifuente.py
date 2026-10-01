"""Las tres fuentes habilitan todo el pipeline: enrich → correlate → report (con IA).

Ninguna prueba sale a la red: las tres fuentes se configuran y su `consultar` se sustituye.
El LLM se parchea con un stub que registra el prompt.
"""

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import SecretStr

from app.api.indicators import get_vector_store
from app.core.config import settings
from app.db.repositories import indicator_repository
from app.enrichment.client import ReputationAPIError
from app.enrichment.providers import base, virustotal
from app.enrichment.providers.base import CuotaExcedida, Ventana
from app.enrichment.providers.otx import OTX
from app.enrichment.providers.threatfox import ThreatFox
from app.enrichment.providers.virustotal import VirusTotal
from app.main import app as fastapi_app
from tests.conftest import FakeVectorStore

HASH = "24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c"

OTX_VACIO = {"pulse_info": {"count": 0, "pulses": []}}
OTX_EMOTET = {"pulse_info": {"count": 2, "pulses": [
    {"indicator_count": 40, "malware_families": [{"display_name": "Emotet"}], "tags": ["banker"],
     "attack_ids": [{"id": "T9001"}], "references": ["https://blog.example/emotet", "javascript:alert(1)"]},
    {"indicator_count": 12, "malware_families": [{"display_name": "Emotet"}], "tags": []},
]}}
OTX_LISTA_BLANCA = {"pulse_info": {"count": 0, "pulses": []}, "validation": [{"source": "whitelist"}]}
TF_VACIO = {"query_status": "no_result", "data": "Your search did not yield any results"}
TF_EMOTET = {"query_status": "ok", "data": [
    {"malware_printable": "Emotet", "threat_type": "payload", "confidence_level": 90,
     "first_seen": "2026-09-30 10:00:00 UTC", "tags": ["epoch5"], "reference": "https://abuse.example/1"},
]}
TF_DESCONOCIDO = {"query_status": "ok", "data": [
    {"malware_printable": "Unknown malware", "threat_type": "botnet_cc", "confidence_level": 50, "tags": []},
]}
TF_APT = {"query_status": "ok", "data": [{"malware_printable": "APT-Falso", "confidence_level": 80}]}
VT_NO_ENCONTRADO = {"no_encontrado": True}


def _vt(maliciosos=0, nombres=()):
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": maliciosos, "suspicious": 0, "undetected": 70 - maliciosos, "harmless": 0},
        "popular_threat_classification": {"popular_threat_name": [{"value": n} for n in nombres]},
    }}}


VT_LIMPIO = _vt(0)
VT_GEODO = _vt(55, ["geodo"])  # alias de emotet en el índice sintético

TEXTOS = {
    "T9001": {"document": "Falsa Uno (Initial Access)\n\nTexto oficial uno.",
              "metadata": {"nombre": "Falsa Uno", "tactica": "Initial Access"}},
    "T9002": {"document": "Falsa Dos (Execution)\n\nTexto oficial dos.",
              "metadata": {"nombre": "Falsa Dos", "tactica": "Execution"}},
}
SALIDA_LLM = {
    "resumen": "Indicador asociado a Emotet.",
    "hallazgos": [{"afirmacion": "Lo reportan las fuentes.", "tipo": "evidencia", "fuentes": ["E-COR"]}],
}


@pytest.fixture
def fuentes(monkeypatch):
    """Las tres fuentes configuradas, con respuestas (o excepciones) controlables."""
    monkeypatch.setattr(settings, "THREATFOX_API_KEY", SecretStr("k"))
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", SecretStr("k"))
    estado = SimpleNamespace(otx=OTX_VACIO, tf=TF_VACIO, vt=VT_NO_ENCONTRADO, llamadas=[])

    def _hace(nombre):
        def _consultar(self, tipo, valor):
            estado.llamadas.append(nombre)
            respuesta = getattr(estado, nombre)
            if isinstance(respuesta, Exception):
                raise respuesta
            return respuesta
        return _consultar

    monkeypatch.setattr(OTX, "consultar", _hace("otx"))
    monkeypatch.setattr(ThreatFox, "consultar", _hace("tf"))
    monkeypatch.setattr(VirusTotal, "consultar", _hace("vt"))
    return estado


@pytest.fixture
def llm():
    """Vector store con texto para T9001/T9002 y LLM stub que guarda los prompts."""
    prompts = []

    def _generar(prompt, validar):
        prompts.append(prompt)
        return validar(json.dumps(SALIDA_LLM)), {"proveedor": "stub", "modelo": "m", "latencia_ms": 1}

    fastapi_app.dependency_overrides[get_vector_store] = lambda: FakeVectorStore(TEXTOS)
    with patch("app.ai_component.service.generate_analysis", _generar):
        yield prompts
    # El fixture `client` restaura los overrides al terminar.


def _pipeline(client, db):
    """enrich → correlate → report sobre un hash nuevo. Devuelve las tres respuestas."""
    ind = indicator_repository.create(db, {"tipo": "hash", "valor": HASH})
    enrich = client.post(f"/indicators/{ind.id}/enrich")
    assert enrich.status_code == 200, enrich.text
    corr = client.post(f"/indicators/{ind.id}/correlate")
    assert corr.status_code == 200, corr.text
    rep = client.post(f"/indicators/{ind.id}/report")
    assert rep.status_code == 201, rep.text
    return enrich.json(), corr.json(), rep.json()


def _estados(enrich):
    return {f["fuente"]: f["estado"] for f in enrich["fuentes"]}


# --- 1 y 2: una sola fuente basta ---


@pytest.mark.parametrize("fuente, respuesta", [("tf", TF_EMOTET), ("vt", VT_GEODO)])
def test_evidencia_en_una_sola_fuente_habilita_todo_el_pipeline(client, db, fuentes, llm, fuente, respuesta):
    setattr(fuentes, fuente, respuesta)
    nombre = {"tf": "threatfox", "vt": "virustotal"}[fuente]
    enrich, corr, rep = _pipeline(client, db)

    assert enrich["tiene_evidencia"] is True and enrich["cobertura"] == "completa"
    assert _estados(enrich) == {"alienvault_otx": "sin_evidencia", **{
        n: ("con_evidencia" if n == nombre else "sin_evidencia") for n in ("threatfox", "virustotal")}}
    assert corr["resuelto"] is True and corr["entity"]["nombre"] == "emotet"
    assert corr["fuentes"] == [nombre]
    assert all(t["fuentes"] == [nombre] for t in corr["tecnicas"])

    meta = rep["metadatos"]
    assert meta["ia"]["estado"] == "generado" and len(llm) == 1
    assert meta["confianza"]["nivel"] == "media"
    etiqueta = {"threatfox": "ThreatFox", "virustotal": "VirusTotal"}[nombre]
    assert f"- **Respaldada por:** {etiqueta}" in rep["contenido"]
    assert f"vía entidad: {etiqueta}" in rep["contenido"]


# --- 3: las tres coinciden ---


def test_tres_fuentes_coincidentes_dan_procedencia_multiple_y_confianza_alta(client, db, fuentes, llm):
    fuentes.otx, fuentes.tf, fuentes.vt = OTX_EMOTET, TF_EMOTET, VT_GEODO
    enrich, corr, rep = _pipeline(client, db)

    assert set(_estados(enrich).values()) == {"con_evidencia"}
    assert corr["fuentes"] == ["alienvault_otx", "threatfox", "virustotal"]
    assert "respaldado por 2 pulse(s)" in corr["evidencia"] and "ThreatFox familias = 'Emotet'" in corr["evidencia"]
    t9001 = next(t for t in corr["tecnicas"] if t["id"] == "T9001")
    assert t9001["fuentes"] == ["alienvault_otx", "threatfox", "virustotal"]
    assert t9001["reportada_por"] == ["alienvault_otx"]  # OTX cita el ID en attack_ids

    meta = rep["metadatos"]
    assert meta["confianza"]["nivel"] == "alta" and meta["contradicciones"] == []
    assert "respaldada por 3 fuentes" in meta["confianza"]["motivos"][0]
    assert "**Nivel de confianza:** Alta" in rep["contenido"]
    assert "citada por AlienVault OTX" in rep["contenido"]
    assert "Fuentes que respaldan la asociación: AlienVault OTX, ThreatFox, VirusTotal." in llm[0]
    assert "E-OTX" in llm[0] and "E-TF" in llm[0] and "E-VT" in llm[0]


# --- 4: contradicciones ---


def test_vt_sin_detecciones_contradice_a_otx(client, db, fuentes, llm):
    fuentes.otx, fuentes.vt = OTX_EMOTET, VT_LIMPIO
    _, corr, rep = _pipeline(client, db)

    meta = rep["metadatos"]
    [c] = meta["contradicciones"]
    assert c["tipo"] == "vt_limpio" and c["fuentes"] == ["virustotal", "alienvault_otx"]
    assert meta["confianza"]["nivel"] == "baja"
    assert "### Contradicciones\n\n- ⚠ VirusTotal: 0 de 70 motores lo detectan" in rep["contenido"]
    assert "CONTRADICCIÓN detectada por NEXO: VirusTotal: 0 de 70" in llm[0]


def test_familia_que_apunta_a_otra_entidad_es_contradiccion(client, db, fuentes, llm):
    fuentes.otx, fuentes.tf = OTX_EMOTET, TF_APT
    _, corr, rep = _pipeline(client, db)

    # Empate en fuentes (1 y 1): desempata el nº de votos (2 pulses de OTX).
    assert corr["entity"]["nombre"] == "emotet"
    meta = rep["metadatos"]
    assert [c["tipo"] for c in meta["contradicciones"]] == ["entidad_distinta"]
    assert meta["confianza"]["nivel"] == "baja"
    assert "ThreatFox reporta familias que ATT&CK asocia a apt-falso" in rep["contenido"]


def test_lista_blanca_de_otx_contradice_a_otra_fuente(client, db, fuentes, llm):
    fuentes.otx, fuentes.tf = OTX_LISTA_BLANCA, TF_EMOTET
    _, _, rep = _pipeline(client, db)
    meta = rep["metadatos"]
    assert [c["tipo"] for c in meta["contradicciones"]] == ["lista_blanca"]


# --- 5: una fuente falla y otra tiene evidencia ---


def test_fuente_caida_no_detiene_el_pipeline_y_el_informe_la_marca(client, db, fuentes, llm):
    fuentes.otx = ReputationAPIError("fallo de red consultando OTX: timeout")
    fuentes.tf = TF_EMOTET
    fuentes.vt = CuotaExcedida("VirusTotal alcanzó su límite de consultas (429)")
    enrich, corr, rep = _pipeline(client, db)

    assert _estados(enrich) == {"alienvault_otx": "error", "threatfox": "con_evidencia", "virustotal": "limite_cuota"}
    assert enrich["cobertura"] == "parcial" and corr["resuelto"] is True
    meta = rep["metadatos"]
    assert meta["cobertura"] == "parcial"
    # En el informe (solo caché) las que fallaron no tienen respuesta registrada.
    assert {f["fuente"]: f["estado"] for f in meta["fuentes"]}["alienvault_otx"] == "no_disponible"
    assert "**Fuentes no disponibles:** AlienVault OTX (no disponible), VirusTotal (no disponible)" in rep["contenido"]
    assert "no se pudo verificar en AlienVault OTX y VirusTotal" in meta["confianza"]["motivos"][-1]
    assert "Fuentes consultadas que no aportaron datos: AlienVault OTX" in llm[0]


# --- 6: todas responden sin evidencia ---


def test_todas_sin_evidencia_es_sin_evidencia_suficiente_y_completo(client, db, fuentes, llm):
    fuentes.vt = VT_NO_ENCONTRADO
    enrich, corr, rep = _pipeline(client, db)

    assert enrich["tiene_evidencia"] is False and enrich["cobertura"] == "completa"
    assert corr["resuelto"] is False
    meta = rep["metadatos"]
    assert meta["confianza"] == {
        "nivel": "sin_evidencia", "motivos": ["sin registros en AlienVault OTX, ThreatFox y VirusTotal"]}
    assert "Sin evidencia suficiente" in rep["contenido"] and "Fuentes no disponibles" not in rep["contenido"]
    assert meta["ia"]["estado"] == "no_llamado" and llm == []


# --- 7: las tres fallan ---


def test_las_tres_fallan_es_502_nunca_sin_evidencia(client, db, fuentes):
    fuentes.otx = ReputationAPIError("OTX respondió 503")
    fuentes.tf = ReputationAPIError("ThreatFox respondió 500")
    fuentes.vt = CuotaExcedida("VirusTotal alcanzó su límite de consultas (429)")
    ind = indicator_repository.create(db, {"tipo": "hash", "valor": HASH})

    r = client.post(f"/indicators/{ind.id}/enrich")
    assert r.status_code == 502
    for motivo in ("OTX respondió 503", "ThreatFox respondió 500", "429"):
        assert motivo in r.json()["detail"]
    # Sin ninguna respuesta registrada no hay enriquecimiento: correlacionar exige /enrich.
    assert client.post(f"/indicators/{ind.id}/correlate").status_code == 400


# --- 8: la etapa (b) nunca corre si la (a) falla ---


def test_sin_entidad_la_etapa_b_no_se_ejecuta_aunque_haya_evidencia(client, db, fuentes, llm):
    fuentes.tf = TF_DESCONOCIDO  # evidencia real, pero la familia no está en ATT&CK
    with patch("app.correlation.service.retrieve_techniques_for_entity") as etapa_b:
        enrich, corr, rep = _pipeline(client, db)
    etapa_b.assert_not_called()

    assert enrich["tiene_evidencia"] is True and corr["resuelto"] is False and corr["tecnicas"] == []
    meta = rep["metadatos"]
    assert meta["ia"]["estado"] == "no_llamado" and llm == []
    assert meta["confianza"]["nivel"] == "baja"  # una fuente y sin entidad atribuible


# --- consultas de solo lectura y adaptadores ---


def test_get_reconstruye_procedencia_sin_otx_en_cache(client, db, fuentes, llm):
    fuentes.otx = ReputationAPIError("OTX caído")
    fuentes.tf = TF_EMOTET
    ind = indicator_repository.create(db, {"tipo": "hash", "valor": HASH})
    client.post(f"/indicators/{ind.id}/enrich")
    client.post(f"/indicators/{ind.id}/correlate")

    snap = client.get(f"/indicators/{ind.id}").json()
    assert snap["enrichment"]["tiene_evidencia"] is True
    assert snap["correlation"]["fuentes"] == ["threatfox"]
    assert snap["correlation"]["tecnicas"][0]["fuentes"] == ["threatfox"]


def test_resumenes_traen_tecnicas_y_referencias_seguras():
    otx = OTX().resumir(OTX_EMOTET, "hash", HASH)
    assert otx["tecnicas_attck"] == ["T9001"]
    assert otx["referencias"] == ["https://blog.example/emotet"]  # javascript: descartado
    tf = ThreatFox().resumir(TF_EMOTET, "hash", HASH)
    assert tf["referencias"] == ["https://abuse.example/1"] and tf["tecnicas_attck"] == []
    assert base.tecnicas(["t1059.001", "T1059.001", "no", 3]) == ["T1059.001"]


def test_cupo_de_virustotal_no_consulta_de_mas(monkeypatch):
    llamadas = []
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", SecretStr("k"))
    monkeypatch.setattr(virustotal, "CUPO", Ventana(maximo=4, segundos=60))
    monkeypatch.setattr(virustotal, "solicitar", lambda *a, **k: llamadas.append(a) or SimpleNamespace(
        status_code=404))
    for _ in range(4):
        assert VirusTotal().consultar("domain", "a.com") == {"no_encontrado": True}
    with pytest.raises(CuotaExcedida, match="4 consultas/min"):
        VirusTotal().consultar("domain", "a.com")
    assert len(llamadas) == 4, "la 5.ª consulta del minuto no debió salir a la red"
