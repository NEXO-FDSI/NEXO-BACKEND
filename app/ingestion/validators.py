"""Validación de formato de indicadores. Lógica pura: no importa FastAPI ni la BD."""

import ipaddress
import re
from urllib.parse import urlparse

# Sin guiones al inicio/fin de cada etiqueta, TLD alfabético de 2+ caracteres.
_DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$"
)
_HEX_RE = re.compile(r"[a-fA-F0-9]+")
_HASH_LENGTHS = (32, 40, 64)  # MD5, SHA-1, SHA-256


def is_valid_ip(valor: str) -> bool:
    try:
        ipaddress.ip_address(valor)
    except ValueError:
        return False
    return True


def is_valid_domain(valor: str) -> bool:
    return bool(_DOMAIN_RE.match(valor))


def is_valid_hash(valor: str) -> bool:
    return len(valor) in _HASH_LENGTHS and bool(_HEX_RE.fullmatch(valor))


def is_valid_url(valor: str) -> bool:
    if not valor.startswith(("http://", "https://")):
        return False
    partes = urlparse(valor)
    return partes.scheme in {"http", "https"} and bool(partes.netloc)


_VALIDATORS = {
    "ip": is_valid_ip,
    "domain": is_valid_domain,
    "hash": is_valid_hash,
    "url": is_valid_url,
}


def validate_indicator(tipo: str, valor: str) -> bool:
    """¿El valor tiene el formato que corresponde al tipo declarado?"""
    validador = _VALIDATORS.get(tipo)
    return bool(validador and validador(valor))
