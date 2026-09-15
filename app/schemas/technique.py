from pydantic import BaseModel, ConfigDict


class TechniqueBase(BaseModel):
    # el id lo provee el cliente (id oficial ATT&CK, ej. "T1566"), no la base de datos
    id: str
    nombre: str
    tactica: str


class TechniqueCreate(TechniqueBase):
    pass


class TechniqueRead(TechniqueBase):
    model_config = ConfigDict(from_attributes=True)
