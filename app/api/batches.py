from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ai_component.vectorstore import VectorStore
from app.api.correlation import get_attck_index
from app.api.indicators import get_vector_store
from app.correlation.attck_loader import AttckIndex
from app.correlation.lote import correlacionar_lote
from app.db.database import get_db
from app.db.models import Batch, BatchItem, BatchReport, BatchValidation, Indicator
from app.ingestion.lote import registrar_lote, validar_items
from app.reporting.investigaciones import construir
from app.reporting.lote import generate_batch_report
from app.schemas.batch import (
    MAX_INDICADORES_LOTE,
    BatchCreate,
    BatchCreated,
    BatchItemRead,
    BatchRead,
    BatchReportRead,
    BatchSummary,
    BatchValidationRead,
)
from app.schemas.human_validation import HumanValidationRequest

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
    description=(
        "Los lotes más recientes primero, con cuántos indicadores tienen, cuántas entradas se "
        "descartaron, su último informe conjunto y la decisión vigente sobre ese informe."
    ),
)
def list_batches(limit: int = Query(default=50, ge=1, le=200), db: Session = Depends(get_db)):
    lotes = list(db.scalars(select(Batch).order_by(Batch.id.desc()).limit(limit)))
    ids = [b.id for b in lotes]
    conteos = {
        batch_id: (indicadores, descartados)
        for batch_id, indicadores, descartados in db.execute(
            select(
                BatchItem.batch_id,
                func.count(BatchItem.indicator_id),
                func.count().filter(BatchItem.ingesta.in_(("invalido", "duplicado"))),
            )
            .where(BatchItem.batch_id.in_(ids))
            .group_by(BatchItem.batch_id)
        )
    }
    # DISTINCT ON (Postgres): el último informe de cada lote y la última decisión de cada uno.
    ultimos = {
        r.batch_id: r
        for r in db.scalars(
            select(BatchReport).where(BatchReport.batch_id.in_(ids))
            .order_by(BatchReport.batch_id, BatchReport.id.desc()).distinct(BatchReport.batch_id)
        )
    }
    decisiones = {
        v.batch_report_id: v.decision
        for v in db.scalars(
            select(BatchValidation).where(BatchValidation.batch_report_id.in_([r.id for r in ultimos.values()]))
            .order_by(BatchValidation.batch_report_id, BatchValidation.id.desc()).distinct(BatchValidation.batch_report_id)
        )
    }
    return [
        BatchSummary(
            id=b.id, nombre=b.nombre, timestamp=b.timestamp, indicadores=n, descartados=d,
            ultimo_informe=informe and {"id": informe.id, "conclusion": informe.conclusion, "timestamp": informe.timestamp},
            decision=informe and decisiones.get(informe.id),
        )
        for b in lotes
        for (n, d), informe in [(conteos.get(b.id, (0, 0)), ultimos.get(b.id))]
    ]


def _cargar(db: Session, batch_id: int, index: AttckIndex) -> tuple[Batch, list[BatchItemRead], list[dict]]:
    """Lote, ítems en orden e investigación de cada miembro. Sentencias fijas, no por indicador."""
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Lote no encontrado")
    filas = list(db.execute(
        select(BatchItem, Indicator)
        .outerjoin(Indicator, BatchItem.indicator_id == Indicator.id)
        .where(BatchItem.batch_id == batch_id)
        .order_by(BatchItem.posicion)
    ))
    items = [
        BatchItemRead(
            valor=ind.valor if ind else None,
            **{k: getattr(item, k) for k in ("posicion", "entrada", "tipo", "ingesta", "indicator_id", "motivo")},
        )
        for item, ind in filas
    ]
    # Una consulta por tabla para todo el lote, no por indicador.
    return batch, items, construir(db, [ind for _, ind in filas if ind is not None], index)


@router.get(
    "/batches/{batch_id}",
    summary="Un lote con sus vínculos, informes conjuntos y validaciones",
    description=(
        "Solo lectura: el lote, sus `items` en el orden en que se pegaron (con los descartados y "
        "los indicadores eliminados después), la investigación de cada indicador (misma forma "
        "que `GET /indicators/{id}`), `correlacion` (calculada al vuelo y determinística: "
        "`indicadores` con ref `I1…`, estado, entidad, severidad y confianza; `vinculos` entre "
        "pares con sus `senales` —pulse enfocado de OTX compartido, misma infraestructura, misma "
        "entidad—; `agrupaciones`; `conclusion`; `cobertura`; y `cadena_ataque`, las técnicas "
        "documentadas por táctica: compartir técnicas **no** es una señal), los `informes` "
        "conjuntos (todas las versiones) y las `validaciones` (historial). Solo participan en "
        "vínculos los indicadores con entidad resuelta. **404** si el lote no existe."
    ),
)
def get_batch(
    batch_id: int,
    db: Session = Depends(get_db),
    index: AttckIndex = Depends(get_attck_index),
):
    batch, items, investigaciones = _cargar(db, batch_id, index)
    informes = list(db.scalars(select(BatchReport).where(BatchReport.batch_id == batch_id).order_by(BatchReport.id)))
    validaciones = list(db.scalars(
        select(BatchValidation)
        .where(BatchValidation.batch_report_id.in_([r.id for r in informes]))
        .order_by(BatchValidation.id)
    ))
    return {
        "batch": BatchRead.model_validate(batch),
        "items": items,
        "investigaciones": investigaciones,
        # En memoria, sin consultas: el número de sentencias no cambia con la correlación.
        "correlacion": correlacionar_lote([i.model_dump() for i in items], investigaciones, index),
        "informes": [BatchReportRead.model_validate(r) for r in informes],
        "validaciones": [BatchValidationRead.model_validate(v) for v in validaciones],
    }


@router.post(
    "/batches/{batch_id}/report",
    status_code=status.HTTP_201_CREATED,
    response_model=BatchReportRead,
    summary="Generar el informe conjunto de un lote",
    description=(
        "Una versión nueva del informe conjunto, a partir de lo que ya está persistido (no "
        "enriquece ni correlaciona ningún indicador): conclusión determinística (relación "
        "demostrable o **\"Sin relación demostrable entre los indicadores\"**), tabla de "
        "indicadores, vínculos con su señal y su fuente, cobertura ATT&CK conjunta (compartir "
        "técnicas no prueba relación), indicadores que no participan, cobertura de las fuentes y "
        "un análisis del LLM que cita `E-LOTE`, `E-I#`, `E-V#` y `T####`. El LLM no se llama si "
        "ningún indicador resolvió entidad, y si falla el informe se genera igual. Los miembros "
        "pendientes no impiden el informe: quedan declarados como cobertura parcial. **400** si "
        "ningún indicador del lote está enriquecido; **404** si el lote no existe."
    ),
)
def create_batch_report(
    batch_id: int,
    db: Session = Depends(get_db),
    index: AttckIndex = Depends(get_attck_index),
    vector_store: VectorStore = Depends(get_vector_store),
):
    batch, items, investigaciones = _cargar(db, batch_id, index)
    if not any(inv["enrichment"] for inv in investigaciones):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Ejecuta /enrich en al menos un indicador del lote antes de generar el informe conjunto",
        )
    report = generate_batch_report(db, batch, [i.model_dump() for i in items], investigaciones, index, vector_store)
    respuesta = BatchReportRead.model_validate(report)  # antes del commit: después volvería a consultar
    db.commit()
    return respuesta


@router.post(
    "/batch-reports/{report_id}/validate",
    status_code=status.HTTP_201_CREATED,
    response_model=BatchValidationRead,
    summary="Validar un informe conjunto (analista)",
    description=(
        "Registra la decisión del analista sobre el informe conjunto (la conclusión y los vínculos "
        "de esa versión): `aceptado` o `rechazado`. Cada validación es una fila nueva, así el "
        "historial queda auditable. **404** si el informe no existe; **422** si la decisión no "
        "es válida."
    ),
)
def validate_batch_report(report_id: int, payload: HumanValidationRequest, db: Session = Depends(get_db)):
    if db.get(BatchReport, report_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Informe del lote no encontrado")
    validacion = BatchValidation(batch_report_id=report_id, **payload.model_dump())
    db.add(validacion)
    db.flush()
    respuesta = BatchValidationRead.model_validate(validacion)
    db.commit()
    return respuesta
