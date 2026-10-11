from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.correlation import get_attck_index
from app.correlation.attck_loader import AttckIndex
from app.db.database import get_db
from app.db.models import Batch, BatchItem, Indicator
from app.ingestion.lote import registrar_lote, validar_items
from app.reporting.investigaciones import construir
from app.schemas.batch import (
    MAX_INDICADORES_LOTE,
    BatchCreate,
    BatchCreated,
    BatchItemRead,
    BatchRead,
    BatchSummary,
)

router = APIRouter(tags=["Batches"])

_RESUMEN = {"creado": "creados", "existente": "existentes", "duplicado": "duplicados", "invalido": "invalidos"}


@router.post(
    "/batches",
    status_code=status.HTTP_201_CREATED,
    response_model=BatchCreated,
    summary="Registrar un lote de indicadores",
    description=(
        f"Registra entre 2 y {MAX_INDICADORES_LOTE} indicadores de una vez. Cada ítem se normaliza "
        "y valida como en `POST /indicators`, por separado: un ítem inválido o sin `tipo` queda "
        "`invalido` con su `motivo` y **no aborta el lote**; uno ya registrado se reutiliza "
        "(`existente`, sin 409); dos con el mismo valor canónico son un solo indicador "
        "(`duplicado`). Los indicadores nuevos quedan con `fuente` = `Lote #<id>`. No enriquece "
        "ni correlaciona: eso sigue siendo por indicador. **422** si ningún ítem es válido o si "
        "la petición excede los topes; **409** si otra petición registró el mismo valor a la vez "
        "(dos veces seguidas)."
    ),
)
def create_batch(payload: BatchCreate, db: Session = Depends(get_db)):
    filas = validar_items(payload.indicadores)
    if not any(f["valor"] for f in filas):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Ningún indicador del lote es válido: "
            + "; ".join(f"{f['posicion']}: {f['motivo']}" for f in filas),
        )

    # Un reintento: si otra petición registró el mismo valor entre el SELECT y el INSERT, en el
    # segundo intento ese indicador ya es "existente".
    for _ in range(2):
        try:
            batch, filas_lote = registrar_lote(db, payload.nombre, filas)
            cuenta = Counter(f["ingesta"] for f in filas_lote)
            # La respuesta se arma antes del commit: después, cada atributo volvería a consultarse.
            respuesta = {
                "batch": BatchRead.model_validate(batch),
                "items": filas_lote,
                "resumen": {clave: cuenta[ingesta] for ingesta, clave in _RESUMEN.items()},
            }
            db.commit()
            return respuesta
        except IntegrityError:
            db.rollback()  # sin rollback la sesión queda inutilizable
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Otra petición registró a la vez alguno de estos indicadores; vuelve a intentarlo",
    )


@router.get(
    "/batches",
    response_model=list[BatchSummary],
    summary="Lotes recientes",
    description="Los lotes más recientes primero, con cuántos indicadores tienen y cuántas entradas se descartaron.",
)
def list_batches(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)):
    lotes = list(db.scalars(select(Batch).order_by(Batch.id.desc()).limit(limit)))
    conteos = {
        batch_id: (indicadores, descartados)
        for batch_id, indicadores, descartados in db.execute(
            select(
                BatchItem.batch_id,
                func.count(BatchItem.indicator_id),
                func.count().filter(BatchItem.ingesta.in_(("invalido", "duplicado"))),
            )
            .where(BatchItem.batch_id.in_([b.id for b in lotes]))
            .group_by(BatchItem.batch_id)
        )
    }
    return [
        BatchSummary(id=b.id, nombre=b.nombre, timestamp=b.timestamp, indicadores=n, descartados=d)
        for b in lotes
        for n, d in [conteos.get(b.id, (0, 0))]
    ]


@router.get(
    "/batches/{batch_id}",
    summary="Un lote con la investigación de cada indicador",
    description=(
        "Solo lectura: el lote, sus `items` en el orden en que se pegaron (con los descartados y "
        "los indicadores eliminados después) y la investigación de cada indicador, con la misma "
        "forma que `GET /indicators/{id}`. **404** si el lote no existe."
    ),
)
def get_batch(
    batch_id: int,
    db: Session = Depends(get_db),
    index: AttckIndex = Depends(get_attck_index),
):
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lote no encontrado")

    filas = list(db.execute(
        select(BatchItem, Indicator)
        .outerjoin(Indicator, BatchItem.indicator_id == Indicator.id)
        .where(BatchItem.batch_id == batch_id)
        .order_by(BatchItem.posicion)
    ))
    miembros = [ind for _, ind in filas if ind is not None]
    return {
        "batch": BatchRead.model_validate(batch),
        "items": [
            BatchItemRead(
                valor=ind.valor if ind else None,
                **{k: getattr(item, k) for k in ("posicion", "entrada", "tipo", "ingesta", "indicator_id", "motivo")},
            )
            for item, ind in filas
        ],
        # Una consulta por tabla para todo el lote, no por indicador.
        "investigaciones": construir(db, miembros, index),
    }
