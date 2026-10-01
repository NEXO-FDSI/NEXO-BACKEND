from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.correlation.attck_loader import AttckIndex
from app.correlation.service import correlate_indicator
from app.db.database import get_db
from app.db.repositories import indicator_repository
from app.enrichment.service import detalle_otx

router = APIRouter(tags=["Correlation"])


def get_attck_index(request: Request) -> AttckIndex:
    """Índice cargado una sola vez en el lifespan, nunca por request."""
    return request.app.state.attck_index


@router.post(
    "/indicators/{indicator_id}/correlate",
    summary="Correlacionar un indicador con MITRE ATT&CK",
    description=(
        "Cadena de dos etapas: (a) resuelve una entidad conocida (malware, grupo, "
        "herramienta, campaña) a partir de la evidencia de OTX; (b) solo si (a) resolvió, "
        "recupera las técnicas que ATT&CK documenta para esa entidad. Sin evidencia "
        "suficiente devuelve `resuelto: false` y ninguna técnica. **Requiere haber "
        "ejecutado `/enrich` antes** (**400** si no); **404** si el indicador no existe."
    ),
)
def correlate(
    indicator_id: int,
    db: Session = Depends(get_db),
    index: AttckIndex = Depends(get_attck_index),
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
            detail="Debes ejecutar /enrich para este indicador antes de correlacionar",
        )

    resultado = correlate_indicator(db, indicator, detalle, index)
    db.commit()
    return {"indicator_id": indicator_id, **resultado}
