from datetime import datetime

from pydantic import BaseModel, ConfigDict


class EnrichmentCacheBase(BaseModel):
    indicator_id: int
    fuente_api: str
    respuesta_json: str


class EnrichmentCacheCreate(EnrichmentCacheBase):
    pass


class EnrichmentCacheRead(EnrichmentCacheBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
