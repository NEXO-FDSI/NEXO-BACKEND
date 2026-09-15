from pydantic import BaseModel, ConfigDict


class IndicatorEntityLinkBase(BaseModel):
    indicator_id: int
    entity_id: int
    evidencia: str | None = None
    confianza: float  # 0.0 - 1.0


class IndicatorEntityLinkCreate(IndicatorEntityLinkBase):
    pass


class IndicatorEntityLinkRead(IndicatorEntityLinkBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
