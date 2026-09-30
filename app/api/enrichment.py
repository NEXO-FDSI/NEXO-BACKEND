from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.repositories import indicator_repository
from app.enrichment.client import ReputationAPIError
from app.enrichment.service import FUENTE, get_or_fetch_enrichment

router = APIRouter(tags=["Enrichment"])


@router.post(
    "/indicators/{indicator_id}/enrich",
    summary="Enriquecer un indicador (OTX, ThreatFox, VirusTotal)",
    description=(
        "Consulta el indicador en cada fuente configurada (OTX, ThreatFox, VirusTotal) en "
        "paralelo y guarda cada respuesta en caché: las llamadas siguientes (y `/correlate`, "
        "`/report`) no vuelven a salir a la red. `tiene_evidencia` y `detalle` son de OTX; "
        "`fuentes` trae por fuente su `estado` (`con_evidencia`, `sin_evidencia`, `error`, "
        "`limite_cuota`, `no_soportado`, `no_configurado`, `omitido`) y un resumen normalizado. "
        "Las IPs no públicas no se envían a terceros. **502** si OTX no respondió (nunca se "
        "confunde con 'sin evidencia'); si falla otra fuente, 200 con su estado. **404** si "
        "el indicador no existe."
    ),
)
def enrich_indicator(indicator_id: int, db: Session = Depends(get_db)):
    indicator = indicator_repository.get(db, indicator_id)
    if indicator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Indicador no encontrado"
        )

    try:
        resultado = get_or_fetch_enrichment(db, indicator)
        db.commit()
    except ReputationAPIError as exc:
        # commit y no rollback: lo único pendiente son las cachés de las fuentes que SÍ
        # respondieron. Guardarlas hace que "Reintentar" solo vuelva a consultar OTX y no
        # gaste otra vez cuota de VirusTotal (4 consultas/min) por datos que ya tenemos.
        db.commit()
        # 502 y nunca 200 'sin evidencia': no pude verificar != verifiqué y no hay nada.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"El servicio de reputación no respondió: {exc}",
        )

    return {"indicator_id": indicator_id, "fuente": FUENTE, **resultado}
