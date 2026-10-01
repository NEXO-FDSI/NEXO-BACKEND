"""ThreatFox (abuse.ch): IoCs recientes con familia de malware estructurada."""

from urllib.parse import quote

from app.core.config import settings
from app.enrichment.client import ReputationAPIError
from app.enrichment.providers.base import resumen, solicitar, unicos, urls

_URL = "https://threatfox-api.abuse.ch/api/v1/"


class ThreatFox:
    nombre = "threatfox"
    etiqueta = "ThreatFox"
    tipos = frozenset({"ip", "domain", "hash", "url"})

    @property
    def configurado(self) -> bool:
        return bool(settings.THREATFOX_API_KEY.get_secret_value())

    def soporta(self, tipo: str, valor: str) -> bool:
        # search_hash solo acepta MD5 y SHA-256: un SHA-1 daría "illegal_hash".
        return tipo in self.tipos and not (tipo == "hash" and len(valor) == 40)

    def consultar(self, tipo: str, valor: str) -> dict:
        # Solo búsqueda: nunca se envía ni reporta nada a ThreatFox. search_ioc con una IP
        # sin puerto encuentra también sus entradas "ip:puerto".
        cuerpo = (
            {"query": "search_hash", "hash": valor}
            if tipo == "hash"
            else {"query": "search_ioc", "search_term": valor}
        )
        r = solicitar(
            "POST", _URL, self.etiqueta, json=cuerpo,
            headers={"Auth-Key": settings.THREATFOX_API_KEY.get_secret_value()},
        )
        if r.status_code != 200:
            raise ReputationAPIError(f"ThreatFox respondió {r.status_code}")
        try:
            datos = r.json()
        except ValueError as exc:
            raise ReputationAPIError("ThreatFox devolvió un cuerpo no-JSON") from exc
        estado = datos.get("query_status")
        if estado not in ("ok", "no_result"):
            raise ReputationAPIError(f"ThreatFox rechazó la consulta: {estado}")
        return datos

    def resumir(self, crudo: dict, tipo: str, valor: str) -> dict:
        iocs = [i for i in crudo.get("data") or [] if isinstance(i, dict)]
        confianzas = [c for i in iocs if isinstance(c := i.get("confidence_level"), int)]
        vistos = sorted(str(f) for i in iocs for f in (i.get("first_seen"), i.get("last_seen")) if f)
        confianza = max(confianzas, default=None)
        return resumen(
            tiene_evidencia=bool(iocs),
            veredicto=(
                "sin_evidencia" if not iocs
                else "malicioso" if (confianza or 0) >= 50 else "sospechoso"
            ),
            familias=unicos(i.get("malware_printable") for i in iocs),
            etiquetas=unicos(
                [i.get("threat_type") for i in iocs] + [t for i in iocs for t in i.get("tags") or []]
            ),
            detecciones={"registros": len(iocs)} if iocs else None,
            confianza=confianza,
            primera_vez=vistos[0] if vistos else None,
            ultima_vez=vistos[-1] if vistos else None,
            referencias=urls(i.get("reference") for i in iocs),
            referencia_url=f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(valor, safe='')}",
        )
