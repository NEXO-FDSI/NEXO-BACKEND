from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración centralizada, leída desde .env."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    TEST_DATABASE_URL: str = ""  # Postgres efímero en Docker; solo para tests
    REPUTATION_API_KEY: str = ""
    CORS_ORIGINS: str = ""
    ATTCK_STIX_PATH: str = "data/attck/enterprise-attack-19.1.json"

    # Componente de IA. Los valores por defecto apuntan al Ollama local: no son
    # secretos y sirven tal cual en desarrollo.
    LLM_BASE_URL: str = "http://localhost:11434/v1"
    LLM_API_KEY: str = "ollama"
    LLM_MODEL: str = "qwen3:8b"
    EMBEDDING_MODEL: str = "nomic-embed-text"
    CHROMA_PERSIST_DIR: str = "./data/chroma"

    @field_validator("CORS_ORIGINS")
    @classmethod
    def _sin_comodin(cls, v: str) -> str:
        # Con allow_credentials=True un "*" dejaría a cualquier sitio llamar a la API con
        # las cookies del usuario. Se falla al arrancar, no en silencio.
        if "*" in (o.strip() for o in v.split(",")):
            raise ValueError("CORS_ORIGINS no admite '*': lista los orígenes explícitos")
        return v

    @property
    def cors_origins(self) -> list[str]:
        # ponytail: CORS_ORIGINS es str y no list[str] porque pydantic-settings
        # exige formato JSON para tipos complejos y el .env usa CSV.
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
