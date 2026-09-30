"""Cliente del servicio de IA. SDK de OpenAI contra cualquier endpoint compatible.

Ollama, Groq y OpenRouter exponen /v1/chat/completions con el mismo protocolo, así que un
"proveedor" es solo un perfil de configuración (URL, clave, modelo, parámetros), no una
clase. Se prueba el primario y, si falla, el respaldo.
"""

import logging
import time
from dataclasses import dataclass
from functools import lru_cache

from openai import OpenAI

from app.core.config import settings

logger = logging.getLogger(__name__)


class LLMServiceError(RuntimeError):
    """Fallo del servicio de IA: timeout, error de conexión o respuesta inservible.

    `intentos` lista cada perfil probado y su error, para dejar rastro de por qué no
    hubo análisis.
    """

    def __init__(self, mensaje: str, intentos: list[dict] | None = None):
        super().__init__(mensaje)
        self.intentos = intentos or []


@dataclass(frozen=True)
class Perfil:
    proveedor: str  # etiqueta para logs y metadatos del informe
    base_url: str
    api_key: str
    modelo: str
    reasoning_effort: str  # "" = no se envía: no todos los modelos aceptan todos los valores
    timeout: float


def perfiles() -> list[Perfil]:
    """Primario y, si está configurado, respaldo. Se lee de settings en cada llamada."""
    lista = [
        Perfil(
            settings.LLM_PROVIDER,
            settings.LLM_BASE_URL,
            settings.LLM_API_KEY.get_secret_value(),
            settings.LLM_MODEL,
            settings.LLM_REASONING_EFFORT,
            settings.LLM_TIMEOUT,
        )
    ]
    if settings.LLM_FALLBACK_PROVIDER:
        lista.append(
            Perfil(
                settings.LLM_FALLBACK_PROVIDER,
                settings.LLM_FALLBACK_BASE_URL,
                settings.LLM_FALLBACK_API_KEY.get_secret_value(),
                settings.LLM_FALLBACK_MODEL,
                settings.LLM_FALLBACK_REASONING_EFFORT,
                settings.LLM_FALLBACK_TIMEOUT,
            )
        )
    return lista


@lru_cache(maxsize=8)
def _cliente(base_url: str, api_key: str, timeout: float) -> OpenAI:
    # Cacheado por perfil: la siembra hace ~700 llamadas y no necesita ~700 clientes httpx.
    # max_retries=0 porque el SDK reintenta 2 veces por defecto: eso triplicaría la espera.
    # El reintento real es el perfil de respaldo.
    return OpenAI(base_url=base_url, api_key=api_key, timeout=timeout, max_retries=0)


def embed_text(text: str) -> list[float]:
    """Embedding de un texto. Sin envoltura: si la siembra falla, que falle ruidosa.

    Usa su propio endpoint (EMBEDDING_BASE_URL): apuntar el chat a Groq, que no ofrece
    embeddings, no debe romper la siembra.
    """
    cliente = _cliente(
        settings.EMBEDDING_BASE_URL,
        settings.EMBEDDING_API_KEY.get_secret_value(),
        settings.LLM_TIMEOUT,
    )
    return cliente.embeddings.create(model=settings.EMBEDDING_MODEL, input=text).data[0].embedding


def _completar(perfil: Perfil, prompt: str):
    extra = {"reasoning_effort": perfil.reasoning_effort} if perfil.reasoning_effort else {}
    try:
        # reasoning_effort=none apaga el razonamiento en qwen3. Medido con qwen3:8b local:
        # 67.5s razonando contra 19.3s sin razonar. gpt-oss en Groq no acepta "none" (400):
        # por eso es configurable por perfil y no un valor fijo.
        respuesta = _cliente(perfil.base_url, perfil.api_key, perfil.timeout).chat.completions.create(
            model=perfil.modelo,
            messages=[{"role": "user", "content": prompt}],
            extra_body=extra,
        )
    except Exception as e:  # timeout, conexión rechazada, 4xx/5xx del proveedor
        raise LLMServiceError(f"fallo del servicio de IA: {e}") from e

    texto = (respuesta.choices[0].message.content or "").strip()
    if not texto:
        raise LLMServiceError("el servicio de IA devolvió una respuesta vacía")
    return texto, respuesta.usage


def generate_analysis(prompt: str) -> tuple[str, dict]:
    """Redacta el análisis con el primer perfil que responda.

    Devuelve (texto, meta) con proveedor, modelo, latencia, tokens e intentos fallidos.
    Levanta LLMServiceError si ninguno respondió. Nunca devuelve un string vacío
    disfrazado de éxito.
    """
    intentos: list[dict] = []
    for perfil in perfiles():
        inicio = time.perf_counter()
        try:
            texto, usage = _completar(perfil, prompt)
        except LLMServiceError as exc:
            logger.warning("IA %s (%s) falló: %s", perfil.proveedor, perfil.modelo, exc)
            intentos.append({"proveedor": perfil.proveedor, "modelo": perfil.modelo, "error": str(exc)})
            continue
        latencia_ms = round((time.perf_counter() - inicio) * 1000)
        logger.info("IA %s (%s) respondió en %d ms", perfil.proveedor, perfil.modelo, latencia_ms)
        return texto, {
            "proveedor": perfil.proveedor,
            "modelo": perfil.modelo,
            "latencia_ms": latencia_ms,
            "tokens": {
                "prompt": getattr(usage, "prompt_tokens", None),
                "respuesta": getattr(usage, "completion_tokens", None),
            },
            "intentos_fallidos": intentos,
        }
    raise LLMServiceError(
        "ningún proveedor de IA respondió: "
        + "; ".join(f"{i['proveedor']}: {i['error']}" for i in intentos),
        intentos,
    )
