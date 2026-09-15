from datetime import datetime

from pydantic import BaseModel, ConfigDict


class IndicatorBase(BaseModel):
    tipo: str  # ip / domain / hash / url
    valor: str
    fuente: str | None = None


class IndicatorCreate(IndicatorBase):
    pass


class IndicatorRead(IndicatorBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp_ingesta: datetime
