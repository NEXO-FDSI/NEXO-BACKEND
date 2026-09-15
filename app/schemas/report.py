from datetime import datetime

from pydantic import BaseModel, ConfigDict


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
