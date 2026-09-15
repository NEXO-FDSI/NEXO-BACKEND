from datetime import datetime

from pydantic import BaseModel, ConfigDict


class HumanValidationBase(BaseModel):
    report_id: int
    decision: str  # aceptado / rechazado
    analista: str | None = None


class HumanValidationCreate(HumanValidationBase):
    pass


class HumanValidationRead(HumanValidationBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
