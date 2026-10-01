from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ai_component.vectorstore import VectorStore
from app.api.correlation import get_attck_index
from app.correlation.attck_loader import AttckIndex
from app.correlation.service import correlation_snapshot
from app.db.database import get_db
from app.db.repositories import indicator_repository
from app.db.repositories.human_validation import list_by_reports
from app.db.repositories.indicator import get_by_valor, list_recientes
from app.db.repositories.report import list_by_indicator
from app.enrichment.service import FUENTE, detalle_otx, get_or_fetch_enrichment
from app.normalization.normalizer import normalize_indicator
from app.reporting.service import generate_report
from app.schemas.human_validation import HumanValidationRead
from app.schemas.indicator import IndicatorCreate, IndicatorRead, IndicatorTipo
from app.schemas.report import ReportRead

# Tags por endpoint y no en el router: FastAPI los concatena, y el informe va en Reports.
router = APIRouter()


def get_vector_store(request: Request) -> VectorStore:
    """Store abierto una sola vez en el lifespan, igual que el índice ATT&CK."""
    return request.app.state.vector_store


@router.post(
    "/indicators",
    status_code=status.HTTP_201_CREATED,
    response_model=IndicatorRead,
    tags=["Indicators"],
    summary="Registrar un indicador",
    description=(
        "Normaliza (refang, minúsculas, forma canónica) y valida el indicador según su "
        "`tipo` (`ip`, `domain`, `hash`, `url`) y lo persiste. **422** si el formato no "
        "corresponde al tipo; **409** si el valor canónico ya estaba registrado."
    ),
)
def create_indicator(payload: IndicatorCreate, db: Session = Depends(get_db)):
    """El formato ya lo validó IndicatorCreate (422). Aquí solo se persiste."""
    try:
        indicator = indicator_repository.create(db, payload.model_dump())
        # El commit es del endpoint: el repositorio solo hace flush a propósito.
        db.commit()
    except IntegrityError:
        # Sin rollback la sesión queda inutilizable (PendingRollbackError).
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="El indicador ya existe"
        )
    return IndicatorRead.model_validate(indicator)


@router.get(
    "/indicators",
    response_model=list[IndicatorRead],
    tags=["Indicators"],
    summary="Listar o buscar indicadores",
    description=(
        "Sin filtros: los indicadores más recientes. Con `tipo` y `valor`: busca por la forma "
        "canónica (el valor se normaliza igual que al registrar, así que `hxxp://evil[.]com` "
        "encuentra `http://evil.com`) y devuelve una lista de 0 o 1 elementos. Resuelve el 409 "
        "de un indicador registrado desde otro navegador. **422** si llega `valor` sin `tipo`."
    ),
)
def list_indicators(
    tipo: IndicatorTipo | None = None,
    valor: str | None = Query(default=None, max_length=2048),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    if valor is None:
        return list_recientes(db, limit)
    if tipo is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Para buscar por valor hace falta el tipo: la forma canónica depende de él",
        )
    indicator = get_by_valor(db, normalize_indicator(tipo, valor))
    return [indicator] if indicator else []


@router.get(
    "/indicators/{indicator_id}",
    tags=["Indicators"],
    summary="Investigación completa de un indicador",
    description=(
        "Reconstruye la investigación desde lo persistido, **sin escribir nada ni salir a la "
        "red**: `enrichment` (misma forma que `/enrich`, desde la caché), `correlation` (misma "
        "forma que `/correlate`; `null` si aún no se ejecutó), `reports` (todas las versiones, "
        "con `metadatos`) y `validations` (historial). **404** si el indicador no existe."
    ),
)
def get_investigation(
    indicator_id: int,
    db: Session = Depends(get_db),
    index: AttckIndex = Depends(get_attck_index),
):
    indicator = indicator_repository.get(db, indicator_id)
    if indicator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Indicador no encontrado"
        )

    detalle = detalle_otx(db, indicator)  # None = /enrich nunca terminó para este indicador
    enrichment = correlation = None
    if detalle is not None:
        enrichment = {
            "indicator_id": indicator_id,
            "fuente": FUENTE,
            **get_or_fetch_enrichment(db, indicator, consultar=False),
        }
        snapshot = correlation_snapshot(db, indicator, detalle, index)
        correlation = {"indicator_id": indicator_id, **snapshot} if snapshot else None

    reports = list_by_indicator(db, indicator_id)
    return {
        "indicator": IndicatorRead.model_validate(indicator),
        "enrichment": enrichment,
        "correlation": correlation,
        "reports": [ReportRead.model_validate(r) for r in reports],
        "validations": [
            HumanValidationRead.model_validate(v) for v in list_by_reports(db, [r.id for r in reports])
        ],
    }


@router.post(
    "/indicators/{indicator_id}/report",
    status_code=status.HTTP_201_CREATED,
    response_model=ReportRead,
    tags=["Reports"],
    summary="Generar el informe de un indicador",
    description=(
        "Correlaciona (idempotente) y redacta el informe: enriquecimiento, entidad, técnicas "
        "ATT&CK y un análisis narrativo del LLM basado solo en el texto oficial de esas "
        "técnicas. Si no hubo entidad o el LLM falla, el informe se genera igual sin ese "
        "apartado. **Requiere haber ejecutado `/enrich` antes** (**400** si no); **404** si "
        "el indicador no existe."
    ),
)
def create_report(
    indicator_id: int,
    db: Session = Depends(get_db),
    index: AttckIndex = Depends(get_attck_index),
    vector_store: VectorStore = Depends(get_vector_store),
):
    indicator = indicator_repository.get(db, indicator_id)
    if indicator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Indicador no encontrado"
        )

    detalle = detalle_otx(db, indicator)
    if detalle is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Debes ejecutar /enrich para este indicador antes de generar el informe",
        )

    report = generate_report(db, indicator, detalle, index, vector_store)
    db.commit()
    return report
