"""Contrato común de las fuentes de enriquecimiento. Sin FastAPI ni base de datos."""

import re
import threading
import time
from collections import deque
from typing import Protocol
from urllib.parse import urlsplit

import httpx

from app.enrichment.client import ReputationAPIError

TIMEOUT = 10.0  # por fuente; las fuentes corren en paralelo, así que no se suman
ESPERA_REINTENTO = 0.5  # segundos
_NO_PERMITIDO = re.compile(r"[^\w .:/@-]")
_NO_PERMITIDO_URL = re.compile(r"[\s<>\"'`]")
_MAX_ETIQUETA = 64
MAX_ETIQUETAS = 10
MAX_REFERENCIAS = 5
_MAX_URL = 300
_TECNICA = re.compile(r"T\d{4}(?:\.\d{3})?")


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


def urls(textos, maximo: int = MAX_REFERENCIAS) -> list[str]:
    """Referencias de terceros: solo http(s) con host, sin repetir y con tope. Terminan como
    enlaces en la UI, así que nada de javascript:, data: ni URLs kilométricas."""
    salida = []
    for texto in textos:
        if not isinstance(texto, str) or len(texto := texto.strip()) > _MAX_URL or texto in salida:
            continue
        partes = urlsplit(texto)
        if partes.scheme in ("http", "https") and partes.netloc and not _NO_PERMITIDO_URL.search(texto):
            salida.append(texto)
    return salida[:maximo]


def tecnicas(ids) -> list[str]:
    """IDs ATT&CK (T#### o T####.###) que trae una fuente, sin repetir y en orden."""
    salida = []
    for i in ids:
        if isinstance(i, str) and _TECNICA.fullmatch(i := i.strip().upper()) and i not in salida:
            salida.append(i)
    return salida


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
    tecnicas_attck: list[str] = (),
    referencias: list[str] = (),
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
        "tecnicas_attck": list(tecnicas_attck),
        "referencias": list(referencias),
    }


class Ventana:
    """Como mucho `maximo` consultas cada `segundos`, sin esperar: si no hay cupo, no se consulta.

    Esperar bloquearía /enrich más allá de los 30 s del frontend; sin cupo, la fuente queda
    "limite_cuota" y el siguiente "Reintentar" la vuelve a intentar (no se cachea un fallo).
    ponytail: en memoria y por proceso; con varios workers, llevarla a Postgres o Redis.
    """

    def __init__(self, maximo: int, segundos: float):
        self.maximo, self.segundos = maximo, segundos
        self._marcas: deque[float] = deque()
        self._lock = threading.Lock()  # las fuentes se consultan desde hilos

    def tomar(self) -> bool:
        ahora = time.monotonic()
        with self._lock:
            while self._marcas and ahora - self._marcas[0] >= self.segundos:
                self._marcas.popleft()
            if len(self._marcas) >= self.maximo:
                return False
            self._marcas.append(ahora)
            return True


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


def describir(r: dict) -> str:
    """Resumen normalizado → una frase. La usan el prompt del LLM y el informe, así una
    fuente nueva aparece en ambos sin tocar ninguno de los dos."""
    partes = [f"veredicto de la fuente: {r['veredicto'].replace('_', ' ')}"]
    detecciones = r.get("detecciones") or {}
    if "pulses" in detecciones:
        partes.append(f"{detecciones['pulses']} pulse(s) de la comunidad lo mencionan")
        if detecciones.get("pulses_masivos"):
            partes.append(f"{detecciones['pulses_masivos']} son volcados masivos y se ignoran")
    if "registros" in detecciones:
        partes.append(f"{detecciones['registros']} registro(s) del indicador")
    if "maliciosos" in detecciones:
        partes.append(
            f"{detecciones['maliciosos']} de {detecciones['total']} motores lo marcan malicioso"
            f" y {detecciones['sospechosos']} sospechoso"
        )
    if r.get("familias"):
        partes.append("familias reportadas: " + ", ".join(r["familias"]))
    if r.get("confianza") is not None:
        partes.append(f"confianza de la fuente: {r['confianza']}/100")
    if r.get("etiquetas"):
        partes.append("etiquetas: " + ", ".join(r["etiquetas"][:5]))
    if r.get("primera_vez"):
        partes.append(f"visto por primera vez: {r['primera_vez']}")
    if r.get("ultima_vez"):
        partes.append(f"visto por última vez: {r['ultima_vez']}")
    return "; ".join(partes) + "."
