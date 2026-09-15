"""Validadores de formato por tipo. Lógica pura: no necesitan base de datos."""

import pytest

from app.ingestion.validators import (
    is_valid_domain,
    is_valid_hash,
    is_valid_ip,
    is_valid_url,
    validate_indicator,
)

VALIDOS = [
    ("ip", "8.8.8.8"),
    ("ip", "::1"),
    ("ip", "2001:4860:4860::8888"),
    ("domain", "example.com"),
    ("domain", "sub.dominio.co"),
    ("hash", "d41d8cd98f00b204e9800998ecf8427e"),                      # MD5, 32
    ("hash", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),              # SHA-1, 40
    ("hash", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),  # SHA-256, 64
    ("url", "https://example.com/path?q=1"),
    ("url", "http://10.0.0.1:8080"),
]

INVALIDOS = [
    ("ip", "no-es-una-ip"),
    ("ip", "999.1.1.1"),
    ("ip", "8.8.8.8/24"),
    ("domain", "-mal.com"),
    ("domain", "sinpunto"),
    ("domain", "example.c"),          # TLD de 1 letra
    ("hash", "abc123"),               # longitud inválida
    ("hash", "z" * 32),               # no es hexadecimal
    ("url", "ftp://example.com"),     # esquema no permitido
    ("url", "example.com"),           # sin esquema
    ("url", "https://"),              # netloc vacío
]


@pytest.mark.parametrize("tipo,valor", VALIDOS, ids=[f"{t}:{v[:20]}" for t, v in VALIDOS])
def test_validos(tipo, valor):
    assert validate_indicator(tipo, valor) is True


@pytest.mark.parametrize("tipo,valor", INVALIDOS, ids=[f"{t}:{v[:20]}" for t, v in INVALIDOS])
def test_invalidos(tipo, valor):
    assert validate_indicator(tipo, valor) is False


def test_formato_debe_coincidir_con_el_tipo_declarado():
    """La regla central de la etapa: un valor válido de otro tipo no sirve."""
    assert is_valid_domain("example.com") and not validate_indicator("ip", "example.com")
    assert is_valid_ip("8.8.8.8") and not validate_indicator("domain", "8.8.8.8")
    assert is_valid_url("https://a.com") and not validate_indicator("hash", "https://a.com")
    assert is_valid_hash("a" * 32) and not validate_indicator("url", "a" * 32)


def test_tipo_desconocido_no_revienta():
    assert validate_indicator("email", "a@b.com") is False
