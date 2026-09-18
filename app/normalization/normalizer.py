"""Normalización de indicadores a forma canónica. Lógica pura: no importa FastAPI ni la BD.

Tolerante a errores por diseño: si un valor no se puede canonizar, se devuelve el mejor
esfuerzo sin lanzar. Decidir si el resultado es válido es trabajo de
app.ingestion.validators, que corre después.
"""

import ipaddress
from urllib.parse import urlsplit, urlunsplit

# Símbolos primero, esquemas al final: así "hxxp[:]//evil[.]com" forma el "://" antes de
# que se reemplace "hxxp://". Con el orden inverso ese caso quedaría en "hxxp://evil.com".
_REFANG = (
    ("[.]", "."),
    ("(.)", "."),
    ("[dot]", "."),
    ("[:]", ":"),
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
)


def refang(valor: str) -> str:
    """Deshace las ofuscaciones típicas de threat intel."""
    for ofuscado, limpio in _REFANG:
        valor = valor.replace(ofuscado, limpio)
    return valor


def normalize_ip(valor: str) -> str:
    limpio = refang(valor.strip())
    try:
        # canoniza IPv6: comprime ceros y baja mayúsculas
        return str(ipaddress.ip_address(limpio))
    except ValueError:
        return limpio


def normalize_domain(valor: str) -> str:
    return refang(valor.strip()).lower().rstrip(".")


def normalize_hash(valor: str) -> str:
    # sin refang: los separadores de defang no aplican a un hash y podrían corromperlo
    return valor.strip().lower()


def normalize_url(valor: str) -> str:
    limpio = refang(valor.strip())
    try:
        partes = urlsplit(limpio)
    except ValueError:
        return limpio
    # solo scheme y host a minúsculas: path/query/fragment pueden ser case-sensitive
    return urlunsplit(
        (partes.scheme.lower(), partes.netloc.lower(), partes.path, partes.query, partes.fragment)
    )


_NORMALIZERS = {
    "ip": normalize_ip,
    "domain": normalize_domain,
    "hash": normalize_hash,
    "url": normalize_url,
}


def normalize_indicator(tipo: str, valor: str) -> str:
    """Forma canónica del valor según su tipo. Nunca lanza."""
    normalizador = _NORMALIZERS.get(tipo)
    return normalizador(valor) if normalizador else valor.strip()
