from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.db.database import Base


def _now():
    return datetime.now(timezone.utc)


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, autoincrement=True)
    tipo = Column(String, nullable=False)  # ip / domain / hash / url
    valor = Column(String, nullable=False, unique=True, index=True)
    fuente = Column(String, nullable=True)
    timestamp_ingesta = Column(DateTime(timezone=True), default=_now)

    enrichments = relationship("EnrichmentCache", back_populates="indicator")
    entity_links = relationship("IndicatorEntityLink", back_populates="indicator")
    reports = relationship("Report", back_populates="indicator")


class EnrichmentCache(Base):
    __tablename__ = "enrichment_cache"

    id = Column(Integer, primary_key=True)
    indicator_id = Column(Integer, ForeignKey("indicators.id"), nullable=False)
    fuente_api = Column(String, nullable=False)
    respuesta_json = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=_now)

    indicator = relationship("Indicator", back_populates="enrichments")


class Entity(Base):
    __tablename__ = "entities"

    id = Column(Integer, primary_key=True)
    nombre = Column(String, nullable=False)
    tipo = Column(String, nullable=False)  # malware / grupo / campaña / herramienta

    indicator_links = relationship("IndicatorEntityLink", back_populates="entity")
    technique_links = relationship("EntityTechniqueLink", back_populates="entity")


class IndicatorEntityLink(Base):
    """Etapa (a) de la cadena de correlación: resolución de entidad."""

    __tablename__ = "indicator_entity_link"

    id = Column(Integer, primary_key=True)
    indicator_id = Column(Integer, ForeignKey("indicators.id"), nullable=False)
    entity_id = Column(Integer, ForeignKey("entities.id"), nullable=False)
    evidencia = Column(Text, nullable=True)
    confianza = Column(Float, nullable=False)  # 0.0 - 1.0

    indicator = relationship("Indicator", back_populates="entity_links")
    entity = relationship("Entity", back_populates="indicator_links")


class Technique(Base):
    __tablename__ = "techniques"

    id = Column(String, primary_key=True)  # id oficial ATT&CK, ej. "T1566"
    nombre = Column(String, nullable=False)
    tactica = Column(String, nullable=False)

    entity_links = relationship("EntityTechniqueLink", back_populates="technique")


class EntityTechniqueLink(Base):
    """Etapa (b) de la cadena de correlación: recuperación de técnicas."""

    __tablename__ = "entity_technique_link"

    id = Column(Integer, primary_key=True)
    entity_id = Column(Integer, ForeignKey("entities.id"), nullable=False)
    technique_id = Column(String, ForeignKey("techniques.id"), nullable=False)
    fuente_attck = Column(String, nullable=True)

    entity = relationship("Entity", back_populates="technique_links")
    technique = relationship("Technique", back_populates="entity_links")


class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True)
    indicator_id = Column(Integer, ForeignKey("indicators.id"), nullable=False)
    contenido = Column(Text, nullable=False)
    nivel_confianza = Column(Float, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=_now)

    indicator = relationship("Indicator", back_populates="reports")
    validations = relationship("HumanValidation", back_populates="report")


class HumanValidation(Base):
    __tablename__ = "human_validation"

    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False)
    decision = Column(String, nullable=False)  # aceptado / rechazado
    analista = Column(String, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=_now)

    report = relationship("Report", back_populates="validations")
