"""Contrato común de las fuentes de enriquecimiento. Sin FastAPI ni base de datos."""

import re
import time
from typing import Protocol

import httpx

from app.enrichment.client import ReputationAPIError

TIMEOUT = 10.0  # por fuente; las fuentes corren en paralelo, así que no se suman
ESPERA_REINTENTO = 0.5  # segundos
_NO_PERMITIDO = re.compile(r"[^\w .:/@-]")
_MAX_ETIQUETA = 64
MAX_ETIQUETAS = 10


class CuotaExcedida(ReputationAPIError):
    """La fuente respondió 429. No es 'sin evidencia' ni un fallo del sistema."""


class Proveedor(Protocol):
    nombre: str  # clave en enrichment_cache.fuente_api
    etiqueta: str  # nombre visible
    tipos: frozenset[str]

    @property
    def configurado(self) -> bool:
        """healthCheck barato: hay credenciales. No se hace ping (gastaría cuota)."""
        ...

    def soporta(self, tipo: str, valor: str) -> bool: ...

    def consultar(self, tipo: str, valor: str) -> dict:
        """Respuesta cruda. Levanta ReputationAPIError (o CuotaExcedida) ante cualquier fallo."""
        ...

    def resumir(self, crudo: dict, tipo: str, valor: str) -> dict:
        """Resumen normalizado (ver `resumen`). Tolerante: un formato inesperado no lanza."""
        ...


def limpiar(texto) -> str | None:
    """Texto de terceros → etiqueta corta y sin caracteres de control ni de marcado.

    Todo lo que viene de una fuente es input no confiable: termina en la UI y en el prompt
    del LLM. Recortar y filtrar el charset quita el espacio para instrucciones inyectadas.
    """
    if not isinstance(texto, str):
        return None
    limpio = _NO_PERMITIDO.sub("", texto).strip()[:_MAX_ETIQUETA].strip()
    return limpio or None


def unicos(textos, maximo: int = MAX_ETIQUETAS) -> list[str]:
    """Etiquetas limpias, sin repetir (sin distinguir mayúsculas), en orden de aparición."""
    vistos, salida = set(), []
    for texto in textos:
        limpio = limpiar(texto)
        if limpio and limpio.lower() not in vistos:
            vistos.add(limpio.lower())
            salida.append(limpio)
    return salida[:maximo]


def resumen(
    *,
    tiene_evidencia: bool,
    veredicto: str,  # malicioso | sospechoso | sin_evidencia | benigno_conocido
    familias: list[str] = (),
    etiquetas: list[str] = (),
    detecciones: dict | None = None,
    confianza: int | None = None,
    primera_vez: str | None = None,
    ultima_vez: str | None = None,
    referencia_url: str | None = None,
) -> dict:
    """Forma única del resumen de cualquier fuente: lo único que ven la UI y el LLM."""
    return {
        "tiene_evidencia": tiene_evidencia,
        "veredicto": veredicto,
        "familias": list(familias),
        "etiquetas": list(etiquetas),
        "detecciones": detecciones,
        "confianza": confianza,
        "primera_vez": primera_vez,
        "ultima_vez": ultima_vez,
        "referencia_url": referencia_url,
    }


def solicitar(metodo: str, url: str, fuente: str, **kwargs) -> httpx.Response:
    """HTTP con un reintento ante fallo de red o 5xx. 429 → CuotaExcedida; 4xx no se reintenta.

    ponytail: un reintento fijo con 0,5 s de espera, sin backoff exponencial ni circuit
    breaker; agregarlos si una fuente empieza a fallar de forma intermitente con tráfico real.
    """
    for intento in range(2):
        try:
            respuesta = httpx.request(metodo, url, timeout=TIMEOUT, **kwargs)
        except httpx.RequestError as exc:
            if intento == 1:
                raise ReputationAPIError(f"fallo de red consultando {fuente}: {exc}") from exc
        else:
            if respuesta.status_code == 429:
                raise CuotaExcedida(f"{fuente} alcanzó su límite de consultas (429)")
            if respuesta.status_code < 500 or intento == 1:
                return respuesta
        time.sleep(ESPERA_REINTENTO)
    raise AssertionError("inalcanzable")
