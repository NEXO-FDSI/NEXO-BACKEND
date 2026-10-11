from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.db.models import Batch, BatchItem, BatchReport, BatchValidation


def eliminar_lote_en_cascada(db: Session, batch: Batch) -> dict[str, int]:
    """Borra el lote y todo lo que cuelga de él. Devuelve cuántas filas por tabla.

    Como en `eliminar_en_cascada` de un indicador: las FK no tienen ON DELETE CASCADE, así que
    se borra en orden (hijos primero) dentro de la transacción del endpoint. Los indicadores
    NO se borran: son investigaciones propias, pueden estar en otros lotes o haberse analizado
    solos. Solo hace flush; el commit es del endpoint.
    """
    def borrar(stmt) -> int:
        return db.execute(stmt.execution_options(synchronize_session=False)).rowcount

    informes = select(BatchReport.id).where(BatchReport.batch_id == batch.id)
    eliminados = {
        "batch_validation": borrar(delete(BatchValidation).where(BatchValidation.batch_report_id.in_(informes))),
        "batch_reports": borrar(delete(BatchReport).where(BatchReport.batch_id == batch.id)),
        "batch_items": borrar(delete(BatchItem).where(BatchItem.batch_id == batch.id)),
        "batches": borrar(delete(Batch).where(Batch.id == batch.id)),
    }
    db.flush()
    return eliminados
