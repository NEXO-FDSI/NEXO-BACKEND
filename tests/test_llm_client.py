"""Perfiles de IA: primario → respaldo. Ningún test toca Groq ni Ollama reales."""

from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from app.ai_component import llm_client
from app.ai_component.llm_client import LLMServiceError, Perfil, generate_analysis
from app.core.config import settings
from app.reporting.template import autoria_ia


@pytest.fixture
def con_respaldo(monkeypatch):
    for campo, valor in {
        "LLM_PROVIDER": "groq", "LLM_MODEL": "qwen/qwen3.8-27b",
        "LLM_FALLBACK_PROVIDER": "ollama", "LLM_FALLBACK_MODEL": "qwen3:8b",
    }.items():
        monkeypatch.setattr(settings, campo, valor)


def _proveedores_caidos(monkeypatch, caidos: set[str]) -> list[str]:
    """Sustituye la llamada HTTP: los proveedores en `caidos` fallan, el resto responde."""
    llamados = []

    def _completar(perfil: Perfil, prompt: str):
        llamados.append(perfil.proveedor)
        if perfil.proveedor in caidos:
            raise LLMServiceError(f"{perfil.proveedor} caído")
        return f"texto de {perfil.proveedor}", SimpleNamespace(prompt_tokens=10, completion_tokens=5)

    monkeypatch.setattr(llm_client, "_completar", _completar)
    return llamados


def test_primario_responde_y_el_respaldo_no_se_toca(con_respaldo, monkeypatch):
    llamados = _proveedores_caidos(monkeypatch, set())
    texto, meta = generate_analysis("prompt")
    assert texto == "texto de groq" and llamados == ["groq"]
    assert meta["proveedor"] == "groq" and meta["modelo"] == "qwen/qwen3.8-27b"
    assert meta["tokens"] == {"prompt": 10, "respuesta": 5} and meta["intentos_fallidos"] == []
    assert isinstance(meta["latencia_ms"], int)


def test_primario_cae_y_responde_el_respaldo(con_respaldo, monkeypatch):
    llamados = _proveedores_caidos(monkeypatch, {"groq"})
    texto, meta = generate_analysis("prompt")
    assert texto == "texto de ollama" and llamados == ["groq", "ollama"]
    assert meta["proveedor"] == "ollama"
    assert meta["intentos_fallidos"] == [
        {"proveedor": "groq", "modelo": "qwen/qwen3.8-27b", "error": "groq caído"}]


def test_todos_caen_levanta_con_el_rastro_de_intentos(con_respaldo, monkeypatch):
    _proveedores_caidos(monkeypatch, {"groq", "ollama"})
    with pytest.raises(LLMServiceError, match="groq caído.*ollama caído") as exc:
        generate_analysis("prompt")
    assert [i["proveedor"] for i in exc.value.intentos] == ["groq", "ollama"]


def test_sin_respaldo_configurado_solo_se_prueba_el_primario(monkeypatch):
    monkeypatch.setattr(settings, "LLM_FALLBACK_PROVIDER", "")
    llamados = _proveedores_caidos(monkeypatch, {settings.LLM_PROVIDER})
    with pytest.raises(LLMServiceError):
        generate_analysis("prompt")
    assert llamados == [settings.LLM_PROVIDER]


class _ClienteFalso:
    """Captura los argumentos de chat.completions.create y de embeddings.create."""

    def __init__(self, contenido="Análisis."):
        self.kwargs = {}
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._crear))
        self.embeddings = SimpleNamespace(create=self._embed)
        self._contenido = contenido

    def _crear(self, **kwargs):
        self.kwargs = kwargs
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self._contenido))],
                               usage=None)

    def _embed(self, **kwargs):
        self.kwargs = kwargs
        return SimpleNamespace(data=[SimpleNamespace(embedding=[0.1, 0.2])])


def _perfil(esfuerzo):
    return Perfil("groq", "https://api.groq.com/openai/v1", "k", "m", esfuerzo, 20.0)


@pytest.mark.parametrize("esfuerzo, extra", [("none", {"reasoning_effort": "none"}), ("", {})])
def test_reasoning_effort_solo_se_envia_si_esta_configurado(monkeypatch, esfuerzo, extra):
    """gpt-oss en Groq responde 400 a reasoning_effort=none: vacío debe omitirlo."""
    falso = _ClienteFalso()
    monkeypatch.setattr(llm_client, "_cliente", lambda *a: falso)
    llm_client._completar(_perfil(esfuerzo), "prompt")
    assert falso.kwargs["extra_body"] == extra


def test_respuesta_vacia_es_fallo(monkeypatch):
    monkeypatch.setattr(llm_client, "_cliente", lambda *a: _ClienteFalso(contenido="   "))
    with pytest.raises(LLMServiceError, match="vacía"):
        llm_client._completar(_perfil("none"), "prompt")


def test_embeddings_usan_su_propio_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://api.groq.com/openai/v1")
    monkeypatch.setattr(settings, "EMBEDDING_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setattr(settings, "EMBEDDING_API_KEY", SecretStr("ollama"))
    urls = []

    def _cliente(base_url, api_key, timeout):
        urls.append(base_url)
        return _ClienteFalso()

    monkeypatch.setattr(llm_client, "_cliente", _cliente)
    assert llm_client.embed_text("texto") == [0.1, 0.2]
    assert urls == ["http://localhost:11434/v1"]


def test_autoria_indica_modelo_y_respaldo():
    meta = {"proveedor": "ollama", "modelo": "qwen3:8b", "latencia_ms": 4100,
            "intentos_fallidos": [{"proveedor": "groq", "modelo": "x", "error": "429"}]}
    linea = autoria_ia(meta)
    assert "ollama · qwen3:8b · 4100 ms" in linea and "respaldo: groq no respondió" in linea
    assert "respaldo" not in autoria_ia({**meta, "intentos_fallidos": []})
