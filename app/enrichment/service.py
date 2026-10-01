"""Enriquecimiento multi-fuente con caché. Orquesta fuentes + persistencia, sin FastAPI.

OTX es obligatoria: la correlación se construye sobre sus pulses, así que si OTX falla se
propaga ReputationAPIError (→ 502). El resto de fuentes nunca tumba el enriquecimiento:
cada una informa su estado. Un fallo nunca se convierte en "sin evidencia".
"""

import ipaddress
import json
import time
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy.orm import Session

from app.db.models import Indicator
from app.db.repositories.enrichment_cache import (
    enrichment_cache_repository,
    get_by_indicator_and_source,
)
from app.enrichment.client import ReputationAPIError
from app.enrichment.providers import PROVEEDORES, CuotaExcedida, Proveedor

FUENTE = "alienvault_otx"
OMITIDO = "dirección no pública: no se envía a terceros"


def es_ip_no_publica(indicator: Indicator) -> bool:
    """IPs privadas, loopback, link-local, reservadas...: consultarlas filtra la red interna."""
    return indicator.tipo == "ip" and not ipaddress.ip_address(indicator.valor).is_global


def detalle_otx(db: Session, indicator: Indicator) -> dict | None:
    """Respuesta de OTX para correlacionar: la cacheada, {} si la IP no se consulta a
    terceros (sin evidencia externa, por diseño), o None si falta ejecutar /enrich."""
    if es_ip_no_publica(indicator):
        return {}
    cacheado = get_by_indicator_and_source(db, indicator.id, FUENTE)
    return json.loads(cacheado.respuesta_json) if cacheado else None


def _de_cache(db: Session, indicator: Indicator, fuente: str, cache: dict[str, dict] | None) -> dict | None:
    if cache is not None:
        return cache.get(fuente)
    cacheado = get_by_indicator_and_source(db, indicator.id, fuente)
    return json.loads(cacheado.respuesta_json) if cacheado else None


def _cronometrar(proveedor: Proveedor, tipo: str, valor: str) -> tuple[dict, int]:
    inicio = time.perf_counter()
    crudo = proveedor.consultar(tipo, valor)
    return crudo, round((time.perf_counter() - inicio) * 1000)


def get_or_fetch_enrichment(
    db: Session,
    indicator: Indicator,
    consultar: bool = True,
    cache: dict[str, dict] | None = None,
) -> dict:
    """Consulta cada fuente (de caché si existe; en paralelo si no) y resume su resultado.

    Devuelve {tiene_evidencia, detalle, fuentes}: los dos primeros son de OTX, como
    siempre; `fuentes` trae el estado y el resumen normalizado de cada una.
    Deja propagar ReputationAPIError si OTX falla.

    consultar=False: solo caché, cero HTTP (lo usa el informe). Una fuente configurada sin
    caché queda "no_disponible": falló o alcanzó su cuota cuando se ejecutó /enrich.
    cache: respuestas crudas ya leídas por fuente ({fuente_api: crudo}); evita una consulta
    por fuente cuando se arman muchas investigaciones en lote.
    """
    tipo, valor = indicator.tipo, indicator.valor
    entradas: dict[str, dict] = {}
    crudos: dict[str, dict] = {}
    errores: dict[str, ReputationAPIError] = {}
    pendientes: dict[str, Proveedor] = {}

    for p in PROVEEDORES:
        entrada = entradas[p.nombre] = {
            "fuente": p.nombre, "etiqueta": p.etiqueta, "estado": None, "resumen": None,
            "error": None, "desde_cache": False, "latencia_ms": None,
        }
        if not p.configurado:
            entrada["estado"] = "no_configurado"
        elif not p.soporta(tipo, valor):
            entrada["estado"] = "no_soportado"
        elif es_ip_no_publica(indicator):
            entrada.update(estado="omitido", error=OMITIDO)
        elif (crudo := _de_cache(db, indicator, p.nombre, cache)) is not None:
            crudos[p.nombre] = crudo  # cero HTTP
            entrada["desde_cache"] = True
        elif consultar:
            pendientes[p.nombre] = p
        else:
            entrada.update(estado="no_disponible", error="sin respuesta registrada de esta fuente")

    if pendientes:
        # Solo el HTTP va a hilos: la Session no es thread-safe, así que la caché se escribe
        # aquí, en el hilo del request. Tiempo total ≈ la fuente más lenta, no la suma.
        with ThreadPoolExecutor(max_workers=len(pendientes)) as pool:
            futuros = {n: pool.submit(_cronometrar, p, tipo, valor) for n, p in pendientes.items()}
        for nombre, futuro in futuros.items():
            try:
                crudo, latencia = futuro.result()
            except ReputationAPIError as exc:
                errores[nombre] = exc
                entradas[nombre].update(
                    estado="limite_cuota" if isinstance(exc, CuotaExcedida) else "error",
                    error=str(exc),
                )
                continue
            crudos[nombre] = crudo
            entradas[nombre]["latencia_ms"] = latencia
            enrichment_cache_repository.create(
                db,
                {"indicator_id": indicator.id, "fuente_api": nombre, "respuesta_json": json.dumps(crudo)},
            )

    if FUENTE in errores:
        raise errores[FUENTE]  # 502 como siempre: nunca "sin evidencia" si OTX no respondió

    proveedores = {p.nombre: p for p in PROVEEDORES}
    for nombre, crudo in crudos.items():
        resumen = proveedores[nombre].resumir(crudo, tipo, valor)
        entradas[nombre].update(
            resumen=resumen,
            estado="con_evidencia" if resumen["tiene_evidencia"] else "sin_evidencia",
        )

    detalle = crudos.get(FUENTE, {})
    # .get() encadenado: un cambio de formato en OTX da 'sin evidencia', no un KeyError.
    pulsos = detalle.get("pulse_info", {}).get("count", 0)
    return {"tiene_evidencia": pulsos > 0, "detalle": detalle, "fuentes": list(entradas.values())}
