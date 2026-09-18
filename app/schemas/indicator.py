from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from app.ingestion.validators import validate_indicator
from app.normalization.normalizer import normalize_indicator

IndicatorTipo = Literal["ip", "domain", "hash", "url"]


class IndicatorBase(BaseModel):
    tipo: str  # ip / domain / hash / url
    valor: str
    fuente: str | None = None


class IndicatorCreate(IndicatorBase):
    tipo: IndicatorTipo

    @model_validator(mode="after")
    def _normalizar_y_validar(self):
        # El orden importa: se canoniza primero y se juzga el valor ya canónico.
        self.valor = normalize_indicator(self.tipo, self.valor)
        if not validate_indicator(self.tipo, self.valor):
            raise ValueError(
                f"'{self.valor}' no tiene formato válido de tipo '{self.tipo}'"
            )
        return self


class IndicatorRead(IndicatorBase):
    # tipo queda como str: Read se construye desde filas ya persistidas, no re-valida.
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp_ingesta: datetime
