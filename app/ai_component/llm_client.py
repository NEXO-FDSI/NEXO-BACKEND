"""Cliente del servicio de IA. SDK de OpenAI apuntado a LLM_BASE_URL (Ollama en desarrollo)."""

from functools import lru_cache

from openai import OpenAI

from app.core.config import settings

TIMEOUT = 30.0


class LLMServiceError(RuntimeError):
    """Fallo del servicio de IA: timeout, error de conexión o respuesta inservible."""


@lru_cache(maxsize=1)
def get_client() -> OpenAI:
    # Cacheado: la siembra hace ~700 llamadas y no necesita ~700 clientes httpx.
    # max_retries=0 porque el SDK reintenta 2 veces por defecto: eso convertiría el
    # timeout de 30s en 90s de espera para el endpoint del informe.
    return OpenAI(
        base_url=settings.LLM_BASE_URL,
        api_key=settings.LLM_API_KEY,
        timeout=TIMEOUT,
        max_retries=0,
    )


def embed_text(text: str) -> list[float]:
    """Embedding de un texto. Sin envoltura: si la siembra falla, que falle ruidosa."""
    respuesta = get_client().embeddings.create(model=settings.EMBEDDING_MODEL, input=text)
    return respuesta.data[0].embedding


def generate_analysis(prompt: str) -> str:
    """Redacta el análisis. Levanta LLMServiceError ante cualquier fallo.

    Nunca devuelve un string vacío disfrazado de éxito.
    """
    try:
        # reasoning_effort=none apaga la cadena de pensamiento del modelo. Medido con
        # qwen3:8b sobre un prompt real: 67.5s razonando contra 19.3s sin razonar, o
        # sea que con razonamiento el análisis SIEMPRE excedía el timeout de 30s y
        # ningún informe llegaba a tener sección narrativa.
        respuesta = get_client().chat.completions.create(
            model=settings.LLM_MODEL,
            messages=[{"role": "user", "content": prompt}],
            extra_body={"reasoning_effort": "none"},
        )
    except Exception as e:  # timeout, conexión rechazada, error del servidor
        raise LLMServiceError(f"fallo del servicio de IA: {e}") from e

    texto = (respuesta.choices[0].message.content or "").strip()
    if not texto:
        raise LLMServiceError("el servicio de IA devolvió una respuesta vacía")
    return texto
