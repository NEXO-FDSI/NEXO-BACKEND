"""AlienVault OTX como fuente. Envuelve app.enrichment.client, que queda intacto."""

from urllib.parse import quote

from app.core.config import settings
from app.correlation.service import MAX_INDICADORES_PULSE
from app.enrichment import client  # el módulo, no el símbolo: así el patch de los tests aplica
from app.enrichment.providers.base import resumen, unicos

# Sección de la página web de OTX (distinta de la sección de la API).
_PAGINA = {"ip": "ip", "domain": "domain", "hash": "file", "url": "url"}
_LISTAS_BLANCAS = {"whitelist", "false_positive"}


class OTX:
    nombre = "alienvault_otx"  # valor histórico de enrichment_cache.fuente_api
    etiqueta = "AlienVault OTX"
    tipos = frozenset({"ip", "domain", "hash", "url"})

    @property
    def configurado(self) -> bool:
        return True  # OTX responde también sin clave (con más límite); es la fuente base

    def soporta(self, tipo: str, valor: str) -> bool:
        return tipo in self.tipos

    def consultar(self, tipo: str, valor: str) -> dict:
        return client.fetch_reputation(tipo, valor, settings.REPUTATION_API_KEY.get_secret_value())

    def resumir(self, crudo: dict, tipo: str, valor: str) -> dict:
        info = crudo.get("pulse_info") or {}
        todos = [p for p in info.get("pulses") or [] if isinstance(p, dict)]
        # Mismo criterio que la correlación (Etapa 9): un pulse con más de 1.000 indicadores
        # es un volcado agregado. Sus familias y tags son ruido ("Detects", "Imphash: ...")
        # y no deben llegar ni a la UI ni al LLM como si describieran este indicador.
        pulses = [p for p in todos if (p.get("indicator_count") or 0) <= MAX_INDICADORES_PULSE]
        cantidad = info.get("count") or 0
        familias = unicos(
            f.get("display_name") if isinstance(f, dict) else f
            for p in pulses
            for f in p.get("malware_families") or []
        )
        en_lista_blanca = any(
            isinstance(v, dict) and v.get("source") in _LISTAS_BLANCAS
            for v in crudo.get("validation") or []
        )
        if cantidad == 0 and en_lista_blanca:
            veredicto = "benigno_conocido"
        elif cantidad == 0:
            veredicto = "sin_evidencia"
        else:
            # Estar en pulses es un reporte comunitario; con familia de malware, es malicioso.
            veredicto = "malicioso" if familias else "sospechoso"
        return resumen(
            tiene_evidencia=cantidad > 0,
            veredicto=veredicto,
            familias=familias,
            etiquetas=unicos(t for p in pulses for t in p.get("tags") or []),
            detecciones={"pulses": cantidad, "pulses_masivos": len(todos) - len(pulses)},
            referencia_url=f"https://otx.alienvault.com/indicator/{_PAGINA[tipo]}/{quote(valor, safe='')}",
        )
