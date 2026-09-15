from pydantic import BaseModel, ConfigDict


class EntityBase(BaseModel):
    nombre: str
    tipo: str  # malware / grupo / campaña / herramienta


class EntityCreate(EntityBase):
    pass


class EntityRead(EntityBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
