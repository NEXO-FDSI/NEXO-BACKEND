from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.correlation.attck_loader import AttckIndex
from app.correlation.service import correlate_indicator
from app.db.database import get_db
from app.db.repositories import indicator_repository
from app.enrichment.service import crudos_enriquecidos, get_or_fetch_enrichment

router = APIRouter(tags=["Correlation"])


def get_attck_index(request: Request) -> AttckIndex:
    """Índice cargado una sola vez en el lifespan, nunca por request."""
    return request.app.state.attck_index


@router.post(
    "/indicators/{indicator_id}/correlate",
    summary="Correlacionar un indicador con MITRE ATT&CK",
    description=(
        "Cadena de dos etapas: (a) resuelve una entidad conocida (malware, grupo, "
        "herramienta, campaña) combinando la evidencia de OTX, ThreatFox y VirusTotal; (b) "
        "solo si (a) resolvió, recupera las técnicas que ATT&CK documenta para esa entidad. "
        "`fuentes` (y `tecnicas[].fuentes`) dice qué fuentes sustentan la entidad; "
        "`tecnicas[].reportada_por`, cuáles citan además ese ID de ATT&CK. Sin evidencia "
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

    crudos = crudos_enriquecidos(db, indicator)
    if crudos is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Debes ejecutar /enrich para este indicador antes de correlacionar",
        )

    enriquecimiento = get_or_fetch_enrichment(db, indicator, consultar=False, cache=crudos)
    resultado = correlate_indicator(db, indicator, enriquecimiento["detalle"], index, enriquecimiento["fuentes"])
    db.commit()
    return {"indicator_id": indicator_id, **resultado}
