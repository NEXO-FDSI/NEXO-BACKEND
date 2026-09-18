"""Enriquecimiento con OTX. Ningún test toca la red: fetch_reputation siempre va mockeado."""

import json
from unittest.mock import patch

import pytest

from app.db.repositories import indicator_repository
from app.db.repositories.enrichment_cache import (
    enrichment_cache_repository,
    get_by_indicator_and_source,
)
import httpx

from app.enrichment.client import (
    ReputationAPIError,
    fetch_reputation,
    resolve_otx_section,
)
from app.enrichment.service import FUENTE, get_or_fetch_enrichment

MOCK_TARGET = "app.enrichment.client.fetch_reputation"


def _otx(count: int) -> dict:
    return {"pulse_info": {"count": count, "pulses": [{"name": "x"}] * count}}


def _indicador(db, tipo="hash", valor="d41d8cd98f00b204e9800998ecf8427e"):
    return indicator_repository.create(db, {"tipo": tipo, "valor": valor})


# --- resolve_otx_section ---


@pytest.mark.parametrize(
    "tipo,valor,esperado",
    [
        ("ip", "8.8.8.8", "IPv4"),
        ("ip", "2001:db8::1", "IPv6"),
        ("domain", "example.com", "domain"),
        ("url", "http://example.com/a", "url"),
        # "file" para los tres tamaños: FileHash-MD5 y compañía dan 404 en OTX.
        ("hash", "a" * 32, "file"),
        ("hash", "a" * 40, "file"),
        ("hash", "a" * 64, "file"),
    ],
)
def test_resolve_otx_section(tipo, valor, esperado):
    assert resolve_otx_section(tipo, valor) == esperado


@pytest.mark.parametrize("tipo,valor", [("hash", "a" * 31), ("email", "a@b.com")])
def test_resolve_otx_section_rechaza_lo_desconocido(tipo, valor):
    with pytest.raises(ValueError):
        resolve_otx_section(tipo, valor)


# --- get_or_fetch_enrichment ---


def test_con_evidencia(db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, return_value=_otx(3)) as mock:
        resultado = get_or_fetch_enrichment(db, ind)

    assert resultado["tiene_evidencia"] is True
    assert resultado["detalle"]["pulse_info"]["count"] == 3
    assert mock.call_count == 1


def test_sin_evidencia(db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, return_value=_otx(0)):
        resultado = get_or_fetch_enrichment(db, ind)

    assert resultado["tiene_evidencia"] is False


def test_segunda_llamada_viene_de_cache(db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, return_value=_otx(2)) as mock:
        primero = get_or_fetch_enrichment(db, ind)
        segundo = get_or_fetch_enrichment(db, ind)

    assert mock.call_count == 1, "la segunda llamada debió salir de caché, sin HTTP"
    assert primero == segundo
    filas = [f for f in enrichment_cache_repository.list(db) if f.indicator_id == ind.id]
    assert len(filas) == 1


def test_lo_cacheado_es_la_respuesta_cruda(db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, return_value=_otx(1)):
        get_or_fetch_enrichment(db, ind)

    fila = get_by_indicator_and_source(db, ind.id, FUENTE)
    assert fila is not None and fila.fuente_api == FUENTE
    assert json.loads(fila.respuesta_json) == _otx(1)


def test_fallo_de_api_se_propaga_no_se_vuelve_sin_evidencia(db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, side_effect=ReputationAPIError("timeout")):
        with pytest.raises(ReputationAPIError):
            get_or_fetch_enrichment(db, ind)

    assert get_by_indicator_and_source(db, ind.id, FUENTE) is None


def test_formato_inesperado_no_revienta(db):
    """Si OTX cambia el formato, el resultado es 'sin evidencia', no un 500."""
    ind = _indicador(db)
    with patch(MOCK_TARGET, return_value={"otra_cosa": 1}):
        assert get_or_fetch_enrichment(db, ind)["tiene_evidencia"] is False


# --- endpoint ---


def test_endpoint_200_con_evidencia(client, db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, return_value=_otx(5)):
        r = client.post(f"/indicators/{ind.id}/enrich")

    assert r.status_code == 200
    cuerpo = r.json()
    assert cuerpo["indicator_id"] == ind.id
    assert cuerpo["fuente"] == FUENTE
    assert cuerpo["tiene_evidencia"] is True
    assert cuerpo["detalle"]["pulse_info"]["count"] == 5


def test_endpoint_200_sin_evidencia(client, db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, return_value=_otx(0)):
        r = client.post(f"/indicators/{ind.id}/enrich")

    assert r.status_code == 200 and r.json()["tiene_evidencia"] is False


def test_endpoint_404_si_no_existe(client):
    r = client.post("/indicators/999999/enrich")
    assert r.status_code == 404 and r.json()["detail"] == "Indicador no encontrado"


def test_endpoint_502_si_la_api_falla(client, db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, side_effect=ReputationAPIError("OTX respondió 503")):
        r = client.post(f"/indicators/{ind.id}/enrich")

    assert r.status_code == 502
    assert "no respondió" in r.json()["detail"]
    # y no dejó rastro en caché: un fallo no se cachea
    assert get_by_indicator_and_source(db, ind.id, FUENTE) is None


def test_endpoint_502_nunca_se_disfraza_de_sin_evidencia(client, db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, side_effect=ReputationAPIError("timeout")):
        r = client.post(f"/indicators/{ind.id}/enrich")

    assert r.status_code != 200
    assert "tiene_evidencia" not in r.json()


def test_endpoint_segunda_llamada_no_repite_http(client, db):
    ind = _indicador(db)
    with patch(MOCK_TARGET, return_value=_otx(1)) as mock:
        primero = client.post(f"/indicators/{ind.id}/enrich")
        segundo = client.post(f"/indicators/{ind.id}/enrich")

    assert primero.status_code == segundo.status_code == 200
    assert primero.json() == segundo.json()
    assert mock.call_count == 1


# --- fetch_reputation: httpx mockeado, cero red ---

HTTPX_TARGET = "app.enrichment.client.httpx.get"


def test_fetch_devuelve_el_json_y_arma_bien_la_url():
    with patch(HTTPX_TARGET, return_value=httpx.Response(200, json=_otx(2))) as mock:
        assert fetch_reputation("hash", "a" * 32, "clave") == _otx(2)

    url = mock.call_args.args[0]
    assert url.endswith(f"/file/{'a' * 32}/general")
    assert mock.call_args.kwargs["headers"] == {"X-OTX-API-KEY": "clave"}


def test_fetch_url_va_percent_encoded():
    with patch(HTTPX_TARGET, return_value=httpx.Response(200, json=_otx(0))) as mock:
        fetch_reputation("url", "http://a.com/x?y=1", "clave")

    url = mock.call_args.args[0]
    assert "http%3A%2F%2Fa.com%2Fx%3Fy%3D1" in url and "//a.com" not in url.split("/url/")[1]


def test_error_incluye_el_motivo_de_otx():
    """El 400 de OTX para un dominio que no puede procesar debe ser legible."""
    cuerpo = {"detail": "Invalid domain (nexo-prueba.example)", "error": "unable to parse"}
    with patch(HTTPX_TARGET, return_value=httpx.Response(400, json=cuerpo)):
        with pytest.raises(ReputationAPIError) as exc:
            fetch_reputation("domain", "nexo-prueba.example", "clave")

    assert "400" in str(exc.value)
    assert "Invalid domain (nexo-prueba.example)" in str(exc.value)


def test_error_cae_a_error_si_no_hay_detail():
    with patch(HTTPX_TARGET, return_value=httpx.Response(403, json={"error": "forbidden"})):
        with pytest.raises(ReputationAPIError, match="forbidden"):
            fetch_reputation("domain", "a.com", "clave")


def test_error_con_cuerpo_html_se_recorta():
    with patch(HTTPX_TARGET, return_value=httpx.Response(502, text="<html>" + "x" * 5000)):
        with pytest.raises(ReputationAPIError) as exc:
            fetch_reputation("domain", "a.com", "clave")

    assert len(str(exc.value)) < 260  # el prefijo + 200 chars de motivo


def test_error_con_cuerpo_vacio():
    with patch(HTTPX_TARGET, return_value=httpx.Response(500, text="")):
        with pytest.raises(ReputationAPIError, match=r"\(sin cuerpo\)"):
            fetch_reputation("domain", "a.com", "clave")


def test_fallo_de_red_es_reputation_api_error():
    with patch(HTTPX_TARGET, side_effect=httpx.ConnectTimeout("agotó el tiempo")):
        with pytest.raises(ReputationAPIError, match="fallo de red"):
            fetch_reputation("ip", "8.8.8.8", "clave")


def test_200_con_cuerpo_no_json_es_error():
    with patch(HTTPX_TARGET, return_value=httpx.Response(200, text="no soy json")):
        with pytest.raises(ReputationAPIError, match="no-JSON"):
            fetch_reputation("ip", "8.8.8.8", "clave")


def test_endpoint_502_propaga_el_motivo(client, db):
    """El detalle del 502 debe llegar al analista, no quedarse en 'no respondió'."""
    ind = _indicador(db, tipo="domain", valor="nexo-prueba.example")
    cuerpo = {"detail": "Invalid domain (nexo-prueba.example)"}
    with patch(HTTPX_TARGET, return_value=httpx.Response(400, json=cuerpo)):
        r = client.post(f"/indicators/{ind.id}/enrich")

    assert r.status_code == 502
    assert "Invalid domain (nexo-prueba.example)" in r.json()["detail"]
