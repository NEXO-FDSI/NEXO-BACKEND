"""Cliente HTTP hacia AlienVault OTX. No conoce la base de datos ni FastAPI."""

import ipaddress
from urllib.parse import quote

import httpx

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
_TIMEOUT = 10.0  # un único intento, sin reintentos ni backoff
_HASH_LENGTHS = (32, 40, 64)  # MD5, SHA-1, SHA-256
_MOTIVO_MAX = 200  # recorta páginas de error HTML enormes


class ReputationAPIError(Exception):
    """La API de reputación no respondió o respondió algo inutilizable.

    Nunca significa 'sin evidencia': significa 'no pude verificar'.
    """


def resolve_otx_section(tipo: str, valor: str) -> str:
    """Sección de la API de OTX que corresponde al tipo de indicador."""
    if tipo == "ip":
        return "IPv4" if ipaddress.ip_address(valor).version == 4 else "IPv6"
    if tipo == "domain":
        return "domain"
    if tipo == "url":
        return "url"
    if tipo == "hash":
        if len(valor) not in _HASH_LENGTHS:
            raise ValueError(f"longitud de hash no reconocida: {len(valor)}")
        # "file" para los tres tamaños, verificado contra la API real. La tabla del spec
        # decía FileHash-MD5/-SHA1/-SHA256, que son los nombres de tipo en los pulses de
        # OTX, no secciones del endpoint: dan 404 "endpoint not found".
        return "file"
    raise ValueError(f"tipo de indicador no soportado: {tipo}")


def _motivo(respuesta: httpx.Response) -> str:
    """Razón legible del error: el campo 'detail' de OTX si viene, o el cuerpo crudo.

    Distingue un problema del indicador ("Invalid domain (...)") de uno del proveedor.
    """
    try:
        cuerpo = respuesta.json()
    except ValueError:
        return respuesta.text.strip()[:_MOTIVO_MAX] or "(sin cuerpo)"

    if isinstance(cuerpo, dict):
        cuerpo = cuerpo.get("detail") or cuerpo.get("error") or cuerpo
    return str(cuerpo)[:_MOTIVO_MAX]


def fetch_reputation(tipo: str, valor: str, api_key: str) -> dict:
    """Consulta la reputación en OTX. Levanta ReputationAPIError ante cualquier fallo."""
    seccion = resolve_otx_section(tipo, valor)
    # safe="": imprescindible para url (/ y : van codificados), inocuo para el resto.
    url = f"{_BASE_URL}/{seccion}/{quote(valor, safe='')}/general"

    try:
        respuesta = httpx.get(url, headers={"X-OTX-API-KEY": api_key}, timeout=_TIMEOUT)
    except httpx.RequestError as exc:
        # RequestError es el padre de TimeoutException y NetworkError.
        raise ReputationAPIError(f"fallo de red consultando OTX: {exc}") from exc

    if respuesta.status_code != 200:
        raise ReputationAPIError(
            f"OTX respondió {respuesta.status_code}: {_motivo(respuesta)}"
        )

    try:
        return respuesta.json()
    except ValueError as exc:
        # Un 200 con cuerpo ilegible es un fallo de la API, no una respuesta sin evidencia.
        raise ReputationAPIError(f"OTX devolvió un cuerpo no-JSON: {exc}") from exc
