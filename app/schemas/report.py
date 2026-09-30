import json
from datetime import datetime

from pydantic import BaseModel, ConfigDict, field_validator


class ReportBase(BaseModel):
    indicator_id: int
    contenido: str
    nivel_confianza: float


class ReportCreate(ReportBase):
    pass


class ReportRead(ReportBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    metadatos: dict | None = None

    @field_validator("metadatos", mode="before")
    @classmethod
    def _desde_json(cls, v):
        # En la BD es Text con JSON; hacia la API sale como objeto.
        return json.loads(v) if isinstance(v, str) else v
