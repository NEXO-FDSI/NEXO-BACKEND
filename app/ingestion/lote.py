"""Ingesta en bloque: un lote de indicadores que define el analista. Sin FastAPI.

Cada ítem se valida por separado con IndicatorCreate (la misma normalización y validación que
POST /indicators): un ítem inválido queda registrado con su motivo y no aborta el lote. Un
indicador ya registrado se reutiliza en vez de dar 409.
"""

from typing import get_args

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Batch, BatchItem, Indicator
from app.schemas.batch import ItemLote
from app.schemas.indicator import IndicatorCreate, IndicatorTipo

TIPOS = get_args(IndicatorTipo)
_COLUMNAS_ITEM = ("posicion", "entrada", "tipo", "ingesta", "indicator_id", "motivo")


def validar_items(items: list[ItemLote]) -> list[dict]:
    """Cada ítem con su valor canónico, o con el motivo por el que se descarta. Puro.

    `ingesta` queda en None para los válidos: creado o existente lo decide la BD.
    Dos entradas con el mismo valor canónico (evil[.]com y EVIL.COM) son un solo indicador:
    la segunda queda "duplicado".
    """
    filas, primera = [], {}
    for posicion, item in enumerate(items, 1):
        fila = {"posicion": posicion, "entrada": item.valor, "tipo": item.tipo, "ingesta": None,
                "indicator_id": None, "valor": None, "motivo": None}
        if item.tipo not in TIPOS:
            motivo = "tipo no reconocido" if item.tipo is None else f"tipo '{item.tipo}' no soportado (ip, domain, hash o url)"
            fila.update(ingesta="invalido", motivo=motivo)
        else:
            try:
                valor = IndicatorCreate(tipo=item.tipo, valor=item.valor).valor
            except ValidationError as exc:
                fila.update(ingesta="invalido", motivo=exc.errors()[0]["msg"].removeprefix("Value error, "))
            else:
                if valor in primera:
                    fila.update(ingesta="duplicado", motivo=f"mismo valor canónico que la posición {primera[valor]}")
                else:
                    primera[valor] = posicion
                    fila["valor"] = valor
        filas.append(fila)
    return filas


def registrar_lote(db: Session, nombre: str | None, filas: list[dict]) -> tuple[Batch, list[dict]]:
    """Persiste el lote: crea los indicadores nuevos y reutiliza los existentes. Sin commit.

    Devuelve el lote y una copia de `filas` con `ingesta`, `indicator_id` y `valor` completos.
    Cuatro sentencias sin importar cuántos ítems: INSERT del lote, un SELECT ... IN, un INSERT
    de los indicadores nuevos y uno de los ítems (add_all + flush; BaseRepository.create haría
    flush + refresh por fila). Puede levantar IntegrityError si otra petición registró el mismo
    valor entre el SELECT y el INSERT: el endpoint decide.
    """
    batch = Batch(nombre=nombre)
    db.add(batch)
    db.flush()  # el id da la fuente de los indicadores nuevos

    filas = [dict(f) for f in filas]
    validas = [f for f in filas if f["valor"]]
    indicadores = {
        i.valor: i for i in db.scalars(select(Indicator).where(Indicator.valor.in_([f["valor"] for f in validas])))
    }
    nuevos = []
    for f in validas:
        if f["valor"] in indicadores:
            f["ingesta"] = "existente"
        else:
            f["ingesta"] = "creado"
            nuevo = indicadores[f["valor"]] = Indicator(tipo=f["tipo"], valor=f["valor"], fuente=f"Lote #{batch.id}")
            nuevos.append(nuevo)
    db.add_all(nuevos)
    db.flush()  # ids de los indicadores nuevos

    for f in validas:
        f["indicator_id"] = indicadores[f["valor"]].id
    db.add_all(BatchItem(batch_id=batch.id, **{k: f[k] for k in _COLUMNAS_ITEM}) for f in filas)
    db.flush()
    return batch, filas
