"""Etapa 8: RAG grounded. Ningún test toca Ollama ni Chroma reales.

El fixture autouse sin_llm_real del conftest hace que cualquier llamada no parcheada al
LLM reviente con AssertionError, así que "el LLM no fue invocado" se afirma solo.
"""

import pytest

from app.ai_component.llm_client import LLMServiceError
from app.ai_component.prompt_builder import MAX_CHARS_DESC, MAX_TECNICAS, build_analysis_prompt
from app.ai_component.service import generate_grounded_analysis
from app.db.models import Indicator
from app.reporting.template import ANALISIS_NO_DISPONIBLE, build_report_content
from tests.conftest import FakeVectorStore

INDICADOR = Indicator(tipo="ip", valor="10.0.0.1")

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
SIN_EVIDENCIA = {
    "resuelto": False, "entity": None, "confianza": None, "evidencia": None, "tecnicas": [],
}

TEXTOS = {
    "T9001": {
        "document": "Falsa Uno (Initial Access)\n\nLos adversarios envían adjuntos maliciosos.",
        "metadata": {"nombre": "Falsa Uno", "tactica": "Initial Access"},
    },
    "T9002": {
        "document": "Falsa Dos (Execution)\n\nLos adversarios abusan de intérpretes de comandos.",
        "metadata": {"nombre": "Falsa Dos", "tactica": "Execution"},
    },
}


# --- construcción del prompt ---


def test_prompt_incluye_reglas_y_texto_de_cada_tecnica():
    prompt = build_analysis_prompt(INDICADOR, RESUELTO, TEXTOS)

    assert "Usa EXCLUSIVAMENTE la información provista abajo" in prompt
    assert "Si algo no está en el contexto provisto, no lo menciones." in prompt
    assert "Indicador: ip — 10.0.0.1" in prompt
    assert "Entidad asociada: emotet (malware)" in prompt
    assert "Confianza de la asociación: 0.9" in prompt
    assert "### T9001 — Falsa Uno (Initial Access)" in prompt
    assert "Los adversarios envían adjuntos maliciosos." in prompt
    assert "### T9002 — Falsa Dos (Execution)" in prompt
    assert "Los adversarios abusan de intérpretes de comandos." in prompt
    assert prompt.endswith("Redacta el párrafo de análisis ahora.")
    # El encabezado ya lleva nombre y táctica: no se repiten dentro del bloque.
    assert "Falsa Uno (Initial Access)\n\nLos adversarios" not in prompt


def test_prompt_recorta_tecnicas_y_descripciones():
    correlation = {
        **RESUELTO,
        "tecnicas": [{"id": f"T{i:04d}", "nombre": f"N{i}", "tactica": "Execution"} for i in range(20)],
    }
    textos = {
        t["id"]: {
            "document": f"{t['nombre']} (Execution)\n\n" + "x" * 2000,
            "metadata": {"nombre": t["nombre"], "tactica": "Execution"},
        }
        for t in correlation["tecnicas"]
    }

    prompt = build_analysis_prompt(INDICADOR, correlation, textos)

    assert prompt.count("### T") == MAX_TECNICAS
    assert f"(se muestran {MAX_TECNICAS} de 20 técnicas asociadas)" in prompt
    assert "x" * MAX_CHARS_DESC + "…" in prompt
    assert "x" * (MAX_CHARS_DESC + 1) not in prompt


def test_prompt_omite_tecnicas_ausentes_del_indice():
    prompt = build_analysis_prompt(INDICADOR, RESUELTO, {"T9001": TEXTOS["T9001"]})
    assert "### T9001" in prompt and "### T9002" not in prompt


# --- orquestación ---


def test_sin_resolver_no_toca_ni_vector_store_ni_llm():
    store = FakeVectorStore(TEXTOS)
    assert generate_grounded_analysis(INDICADOR, SIN_EVIDENCIA, store) is None
    assert store.llamadas == []  # el corte ocurre antes de cualquier recuperación


def test_indice_vacio_no_llama_al_llm():
    store = FakeVectorStore()  # ninguna técnica sembrada
    assert generate_grounded_analysis(INDICADOR, RESUELTO, store) is None
    assert store.llamadas == [["T9001", "T9002"]]  # se consultó, pero no devolvió nada


def test_devuelve_el_texto_del_llm(monkeypatch):
    monkeypatch.setattr(
        "app.ai_component.service.generate_analysis", lambda prompt: "Análisis redactado."
    )
    resultado = generate_grounded_analysis(INDICADOR, RESUELTO, FakeVectorStore(TEXTOS))
    assert resultado == "Análisis redactado."


def test_fallo_del_llm_devuelve_none_sin_propagar(monkeypatch):
    def _revienta(prompt: str) -> str:
        raise LLMServiceError("timeout")

    monkeypatch.setattr("app.ai_component.service.generate_analysis", _revienta)
    assert generate_grounded_analysis(INDICADOR, RESUELTO, FakeVectorStore(TEXTOS)) is None


def test_errores_ajenos_al_servicio_de_ia_si_se_propagan(monkeypatch):
    """Solo LLMServiceError se traga: un bug del código no se esconde."""
    def _bug(prompt: str) -> str:
        raise ValueError("bug real")

    monkeypatch.setattr("app.ai_component.service.generate_analysis", _bug)
    with pytest.raises(ValueError):
        generate_grounded_analysis(INDICADOR, RESUELTO, FakeVectorStore(TEXTOS))


# --- sección de análisis en la plantilla ---


def test_plantilla_con_analisis():
    md = build_report_content(INDICADOR, {}, RESUELTO, "Emotet usa adjuntos maliciosos.")
    assert "## Análisis\n\nEmotet usa adjuntos maliciosos." in md
    assert "no disponible" not in md
    # La narrativa va después de la tabla y antes del estado de validación.
    assert md.index("| T9001 ") < md.index("## Análisis") < md.index("## Estado de validación")


def test_plantilla_con_analisis_fallido():
    md = build_report_content(INDICADOR, {}, RESUELTO, None)
    assert f"## Análisis\n\n{ANALISIS_NO_DISPONIBLE}" in md
    # El contenido determinístico sigue íntegro.
    assert "| T9001 | Falsa Uno | Initial Access |" in md
    assert "**Nivel de confianza:** 0.9" in md


def test_plantilla_sin_evidencia_tambien_lleva_la_nota():
    md = build_report_content(INDICADOR, {}, SIN_EVIDENCIA, None)
    assert "Sin evidencia suficiente" in md
    assert f"## Análisis\n\n{ANALISIS_NO_DISPONIBLE}" in md
