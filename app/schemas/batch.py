import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ponytail: perilla. Con más indicadores conviene procesar el lote en segundo plano en el
# backend (plan de la Fase 7, §2.2): el cupo de VirusTotal y el contexto del LLM no escalan.
MAX_INDICADORES_LOTE = 20

Ingesta = Literal["creado", "existente", "duplicado", "invalido", "eliminado"]
Conclusion = Literal["relacion_demostrable", "sin_relacion_demostrable"]


class ItemLote(BaseModel):
    """Laxo a propósito: un tipo o un valor inválido no tumba el lote, queda registrado como
    'invalido' con su motivo. Los topes de tamaño sí son de la petición (422)."""

    tipo: str | None = Field(default=None, max_length=16)
    valor: str = Field(max_length=2048)


class BatchCreate(BaseModel):
    nombre: str | None = Field(default=None, max_length=200)
    indicadores: list[ItemLote] = Field(min_length=2, max_length=MAX_INDICADORES_LOTE)


class BatchRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    nombre: str | None
    timestamp: datetime


class BatchItemRead(BaseModel):
    posicion: int
    entrada: str  # tal como la pegó el analista
    tipo: str | None
    ingesta: Ingesta
    indicator_id: int | None
    valor: str | None  # canónico; solo si el ítem tiene indicador
    motivo: str | None


class BatchCreated(BaseModel):
    batch: BatchRead
    items: list[BatchItemRead]
    resumen: dict[str, int]  # creados, existentes, duplicados, invalidos


class BatchReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    batch_id: int
    contenido: str  # Markdown
    conclusion: Conclusion
    metadatos: dict | None = None
    timestamp: datetime

    @field_validator("metadatos", mode="before")
    @classmethod
    def _desde_json(cls, v):
        # En la BD es Text con JSON; hacia la API sale como objeto (igual que ReportRead).
        return json.loads(v) if isinstance(v, str) else v


class BatchValidationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    batch_report_id: int
    decision: str  # aceptado / rechazado
    analista: str | None
    timestamp: datetime


class UltimoInforme(BaseModel):
    id: int
    conclusion: Conclusion
    timestamp: datetime


class BatchSummary(BatchRead):
    indicadores: int  # ítems con indicador
    descartados: int  # inválidos y duplicados
    ultimo_informe: UltimoInforme | None
    decision: str | None  # la vigente del último informe; None = pendiente o sin informe
