from pydantic import BaseModel, ConfigDict


class EntityTechniqueLinkBase(BaseModel):
    entity_id: int
    technique_id: str
    fuente_attck: str | None = None


class EntityTechniqueLinkCreate(EntityTechniqueLinkBase):
    pass


class EntityTechniqueLinkRead(EntityTechniqueLinkBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
