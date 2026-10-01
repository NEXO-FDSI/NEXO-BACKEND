"""Registro de fuentes de enriquecimiento.

Agregar una fuente = un archivo en este paquete que cumpla `Proveedor` + una línea aquí.
El orden es el de presentación (UI, informe y desempates de la etapa (a)): OTX primero.
"""

from app.enrichment.providers.base import CuotaExcedida, Proveedor
from app.enrichment.providers.otx import OTX
from app.enrichment.providers.threatfox import ThreatFox
from app.enrichment.providers.virustotal import VirusTotal

PROVEEDORES: list[Proveedor] = [OTX(), ThreatFox(), VirusTotal()]

__all__ = ["PROVEEDORES", "CuotaExcedida", "Proveedor"]
