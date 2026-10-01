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

    def _completar(perfil: Perfil, prompt: str, json: bool = False):
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


def test_respuesta_invalida_pasa_al_respaldo(con_respaldo, monkeypatch):
    """JSON roto del primario = fallo del perfil: responde el respaldo con JSON válido."""
    formatos = []

    def _completar(perfil, prompt, json=False):
        formatos.append(json)
        texto = "esto no es json" if perfil.proveedor == "groq" else '{"ok": true}'
        return texto, SimpleNamespace(prompt_tokens=1, completion_tokens=1)

    def _validar(texto):
        import json as _json
        return _json.loads(texto)  # JSONDecodeError es ValueError

    monkeypatch.setattr(llm_client, "_completar", _completar)
    resultado, meta = generate_analysis("prompt", validar=_validar)
    assert resultado == {"ok": True} and meta["proveedor"] == "ollama"
    assert "formato inválido" in meta["intentos_fallidos"][0]["error"]
    assert formatos == [True, True]  # con validador se pide JSON a ambos


def test_con_validador_se_pide_json_al_proveedor(monkeypatch):
    falso = _ClienteFalso()
    monkeypatch.setattr(llm_client, "_cliente", lambda *a: falso)
    llm_client._completar(_perfil("none"), "prompt", json=True)
    assert falso.kwargs["response_format"] == {"type": "json_object"}
    assert falso.kwargs["temperature"] == 0.2
    llm_client._completar(_perfil("none"), "prompt")
    assert "response_format" not in falso.kwargs


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


def _429(retry_after: str | None):
    import httpx
    from openai import RateLimitError

    headers = {"retry-after": retry_after} if retry_after else {}
    respuesta = httpx.Response(429, headers=headers, request=httpx.Request("POST", "https://llm.example"))
    return RateLimitError("rate limit", response=respuesta, body=None)


class _ClienteCon429(_ClienteFalso):
    def __init__(self, errores):
        super().__init__()
        self.errores, self.llamadas = list(errores), 0

    def _crear(self, **kwargs):
        self.llamadas += 1
        if self.errores:
            raise self.errores.pop(0)
        return super()._crear(**kwargs)


def test_429_con_espera_corta_reintenta_el_mismo_perfil(monkeypatch):
    """Groq gratuito pide ~4 s tras agotar tokens/min: esperar es mejor que caer a Ollama."""
    esperas = []
    cliente = _ClienteCon429([_429("4")])
    monkeypatch.setattr(llm_client, "_cliente", lambda *a: cliente)
    monkeypatch.setattr(llm_client.time, "sleep", esperas.append)
    assert llm_client._completar(_perfil("none"), "prompt")[0] == "Análisis."
    assert cliente.llamadas == 2 and esperas == [4.0]


@pytest.mark.parametrize("errores", [[_429("30")], [_429(None)], [_429("4"), _429("4")]])
def test_429_largo_sin_indicacion_o_repetido_es_fallo(monkeypatch, errores):
    monkeypatch.setattr(llm_client, "_cliente", lambda *a: _ClienteCon429(errores))
    monkeypatch.setattr(llm_client.time, "sleep", lambda s: None)
    with pytest.raises(LLMServiceError, match="rate limit"):
        llm_client._completar(_perfil("none"), "prompt")
