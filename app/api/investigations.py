from math import ceil

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.correlation import get_attck_index
from app.correlation.attck_loader import AttckIndex
from app.db.database import get_db
from app.db.models import Indicator
from app.reporting.investigaciones import construir

router = APIRouter(tags=["Investigations"])

TAMANO_MAXIMO = 10  # por página: evita respuestas enormes (cada informe trae su trazabilidad)


@router.get(
    "/investigations",
    summary="Todas las investigaciones, paginadas",
    description=(
        "Investigaciones completas de la plataforma (indicador, enriquecimiento, correlación, "
        "informes con `metadatos` y validaciones), de la más reciente a la más antigua, en "
        f"páginas de hasta {TAMANO_MAXIMO}. Solo lectura. El `detalle` de OTX viaja recortado "
        "a los campos que usa la interfaz, como en `/enrich`. Una página fuera de rango "
        "devuelve `items: []`."
    ),
)
def list_investigations(
    page: int = Query(default=1, ge=1),
    size: int = Query(default=TAMANO_MAXIMO, ge=1, le=TAMANO_MAXIMO),
    db: Session = Depends(get_db),
    index: AttckIndex = Depends(get_attck_index),
):
    total = db.scalar(select(func.count()).select_from(Indicator)) or 0
    indicators = list(
        db.scalars(select(Indicator).order_by(Indicator.id.desc()).offset((page - 1) * size).limit(size))
    )
    return {
        "items": construir(db, indicators, index),
        "page": page,
        "size": size,
        "total": total,
        "pages": ceil(total / size),
    }
