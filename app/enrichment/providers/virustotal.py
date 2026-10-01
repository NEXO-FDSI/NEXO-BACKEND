"""VirusTotal v3: ratio de detección por motores. Solo consultas GET, nunca envíos."""

import base64
import ipaddress
from datetime import datetime, timezone
from urllib.parse import quote

from app.core.config import settings
from app.enrichment.client import ReputationAPIError
from app.enrichment.providers.base import resumen, solicitar, unicos

_API = "https://www.virustotal.com/api/v3"
_GUI = "https://www.virustotal.com/gui"
UMBRAL_MALICIOSO = 5  # ponytail: motores que marcan malicioso para decir "malicioso"; perilla


def _ruta(tipo: str, valor: str) -> str:
    if tipo == "hash":
        return f"files/{valor}"
    if tipo == "ip":
        return f"ip_addresses/{ipaddress.ip_address(valor)}"
    if tipo == "domain":
        return f"domains/{valor}"
    # El id de una URL es su base64url sin relleno. Nunca POST /urls: eso la escanea
    # (VT la visita) y la hace pública.
    return "urls/" + base64.urlsafe_b64encode(valor.encode()).decode().rstrip("=")


def _fecha(epoch) -> str | None:
    if not isinstance(epoch, int):
        return None
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


class VirusTotal:
    nombre = "virustotal"
    etiqueta = "VirusTotal"
    tipos = frozenset({"ip", "domain", "hash", "url"})

    @property
    def configurado(self) -> bool:
        return bool(settings.VIRUSTOTAL_API_KEY.get_secret_value())

    def soporta(self, tipo: str, valor: str) -> bool:
        return tipo in self.tipos

    def consultar(self, tipo: str, valor: str) -> dict:
        r = solicitar(
            "GET", f"{_API}/{_ruta(tipo, valor)}", self.etiqueta,
            headers={"x-apikey": settings.VIRUSTOTAL_API_KEY.get_secret_value()},
        )
        if r.status_code == 404:
            # VT no conoce el indicador: es "sin registros", no un fallo.
            return {"no_encontrado": True}
        if r.status_code != 200:
            raise ReputationAPIError(f"VirusTotal respondió {r.status_code}")
        try:
            return r.json()
        except ValueError as exc:
            raise ReputationAPIError("VirusTotal devolvió un cuerpo no-JSON") from exc

    def resumir(self, crudo: dict, tipo: str, valor: str) -> dict:
        atributos = (crudo.get("data") or {}).get("attributes") or {}
        stats = atributos.get("last_analysis_stats") or {}
        maliciosos = stats.get("malicious") or 0
        sospechosos = stats.get("suspicious") or 0
        total = sum(stats.get(k) or 0 for k in ("malicious", "suspicious", "undetected", "harmless"))
        clasificacion = atributos.get("popular_threat_classification") or {}
        if maliciosos >= UMBRAL_MALICIOSO:
            veredicto = "malicioso"
        elif maliciosos or sospechosos:
            veredicto = "sospechoso"
        else:
            veredicto = "sin_evidencia"
        pagina = {"hash": "file", "ip": "ip-address", "domain": "domain"}.get(tipo)
        return resumen(
            tiene_evidencia=(maliciosos + sospechosos) > 0,
            veredicto=veredicto,
            familias=unicos(
                (n.get("value") for n in clasificacion.get("popular_threat_name") or [] if isinstance(n, dict)),
                maximo=3,
            ),
            etiquetas=unicos(
                [c.get("value") for c in clasificacion.get("popular_threat_category") or [] if isinstance(c, dict)]
                + list(atributos.get("tags") or [])
            ),
            detecciones={"maliciosos": maliciosos, "sospechosos": sospechosos, "total": total} if stats else None,
            primera_vez=_fecha(atributos.get("first_submission_date")),
            ultima_vez=_fecha(atributos.get("last_analysis_date")),
            referencia_url=(
                f"{_GUI}/{pagina}/{quote(valor, safe='')}" if pagina
                else f"{_GUI}/search/{quote(valor, safe='')}"
            ),
        )
