from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.repositories import indicator_repository
from app.enrichment.client import ReputationAPIError
from app.enrichment.service import FUENTE, get_or_fetch_enrichment
from app.reporting.investigaciones import recortar_otx

router = APIRouter(tags=["Enrichment"])


@router.post(
    "/indicators/{indicator_id}/enrich",
    summary="Enriquecer un indicador (OTX, ThreatFox, VirusTotal)",
    description=(
        "Consulta el indicador en cada fuente configurada (OTX, ThreatFox, VirusTotal) en "
        "paralelo y guarda cada respuesta en caché: las llamadas siguientes (y `/correlate`, "
        "`/report`) no vuelven a salir a la red. `tiene_evidencia` es combinado (alguna fuente "
        "lo encontró); `cobertura` es `parcial` si alguna fuente no se pudo verificar. "
        "`fuentes` trae por fuente su `estado` (`con_evidencia`, `sin_evidencia`, `error`, "
        "`limite_cuota`, `no_soportado`, `no_configurado`, `omitido`) y su evidencia "
        "normalizada (`resumen`). `detalle` es OTX recortado a lo que usa la interfaz; ninguna "
        "respuesta cruda sale de la API (quedan en BD). Las IPs no públicas no se envían a "
        "terceros. **502** solo si fallaron todas las fuentes consultadas (nunca se confunde "
        "con 'sin evidencia'); si falla alguna, 200 con su estado. **404** si el indicador no "
        "existe."
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
        # commit y no rollback, por si algo quedó pendiente en la sesión; hoy, si todas
        # fallaron, no hay cachés nuevas que guardar.
        db.commit()
        # 502 y nunca 200 'sin evidencia': no pude verificar != verifiqué y no hay nada.
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"El servicio de reputación no respondió: {exc}",
        )

    # La respuesta cruda de OTX queda en enrichment_cache (auditoría); no sale de la API.
    resultado["detalle"] = recortar_otx(resultado["detalle"])
    return {"indicator_id": indicator_id, "fuente": FUENTE, **resultado}
