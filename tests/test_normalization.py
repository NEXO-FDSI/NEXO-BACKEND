"""Normalización a forma canónica. Lógica pura: no necesita base de datos."""

import pytest

from app.normalization.normalizer import (
    normalize_indicator,
    normalize_ip,
    normalize_url,
    refang,
)

CASOS = [
    # refang
    ("url", "hxxp://ejemplo[.]com", "http://ejemplo.com"),
    ("url", "hxxps://ejemplo[.]com", "https://ejemplo.com"),
    ("url", "hxxp[:]//evil[.]com", "http://evil.com"),   # motivó reordenar el refang
    ("domain", "ejemplo(.)com", "ejemplo.com"),
    ("domain", "ejemplo[dot]com", "ejemplo.com"),
    ("domain", "ejemplo[.]com", "ejemplo.com"),
    # mayúsculas
    ("domain", "EXAMPLE.COM", "example.com"),
    ("hash", "D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"),
    # trailing dot
    ("domain", "example.com.", "example.com"),
    ("domain", "  EXAMPLE[.]COM.  ", "example.com"),
    # IPv6 comprimido y mayúsculas
    ("ip", "2001:0DB8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
    ("ip", "  8.8.8.8  ", "8.8.8.8"),
    # URL: scheme y host abajo, path/query/fragment intactos
    ("url", "HTTP://Example.COM/Path?Q=1#Frag", "http://example.com/Path?Q=1#Frag"),
    ("url", "hxxps://EVIL[.]COM/AbC", "https://evil.com/AbC"),
]


@pytest.mark.parametrize("tipo,entrada,esperado", CASOS, ids=[f"{t}:{e[:24]}" for t, e, _ in CASOS])
def test_normaliza(tipo, entrada, esperado):
    assert normalize_indicator(tipo, entrada) == esperado


@pytest.mark.parametrize("tipo,entrada,esperado", CASOS, ids=[f"{t}:{e[:24]}" for t, e, _ in CASOS])
def test_idempotente(tipo, entrada, esperado):
    """Normalizar dos veces da lo mismo que una."""
    una = normalize_indicator(tipo, entrada)
    assert normalize_indicator(tipo, una) == una


def test_url_conserva_el_case_del_path():
    """El path puede ser case-sensitive en el servidor destino."""
    assert normalize_url("http://a.com/CaseSensitive") == "http://a.com/CaseSensitive"


def test_hash_no_se_refangea():
    """Un hash hex no lleva separadores defang; tocarlos lo corrompería."""
    assert normalize_indicator("hash", "A" * 32) == "a" * 32


@pytest.mark.parametrize(
    "tipo,entrada",
    [
        ("ip", "no-es-una-ip"),
        ("ip", "999.1.1.1"),
        ("url", "http://[bad"),
        ("domain", "-invalido.com"),
        ("hash", "abc123"),
    ],
)
def test_entrada_invalida_no_lanza(tipo, entrada):
    """Best effort: normalizar nunca decide validez ni revienta."""
    assert isinstance(normalize_indicator(tipo, entrada), str)


def test_ip_invalida_devuelve_mejor_esfuerzo():
    assert normalize_ip("  no-es-una-ip  ") == "no-es-una-ip"


def test_tipo_desconocido_solo_recorta():
    assert normalize_indicator("email", "  Alguien@Ejemplo.com  ") == "Alguien@Ejemplo.com"


def test_refang_aislado():
    assert refang("hxxp[:]//a[.]b(.)c[dot]d") == "http://a.b.c.d"
