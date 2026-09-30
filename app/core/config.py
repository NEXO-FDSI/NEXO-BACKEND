from pydantic import SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración centralizada, leída desde .env."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    TEST_DATABASE_URL: str = ""  # Postgres efímero en Docker; solo para tests
    # SecretStr: si alguien imprime o loguea settings, la clave sale como '**********'.
    REPUTATION_API_KEY: SecretStr = SecretStr("")  # AlienVault OTX
    # Fuentes adicionales: sin clave quedan "no configuradas" y el pipeline sigue con OTX.
    THREATFOX_API_KEY: SecretStr = SecretStr("")
    VIRUSTOTAL_API_KEY: SecretStr = SecretStr("")
    CORS_ORIGINS: str = ""
    ATTCK_STIX_PATH: str = "data/attck/enterprise-attack-19.1.json"
    LOG_LEVEL: str = "INFO"

    # Componente de IA. Cada perfil es un endpoint compatible con OpenAI (Ollama, Groq,
    # OpenRouter...). Los valores por defecto apuntan al Ollama local: no son secretos y
    # sirven tal cual en desarrollo.
    LLM_PROVIDER: str = "ollama"  # solo etiqueta: logs y metadatos del informe
    LLM_BASE_URL: str = "http://localhost:11434/v1"
    LLM_API_KEY: SecretStr = SecretStr("ollama")
    LLM_MODEL: str = "qwen3:8b"
    LLM_REASONING_EFFORT: str = "none"  # vacío = no se envía el parámetro
    LLM_TIMEOUT: float = 60.0
    # Respaldo: se usa solo si el primario falla. LLM_FALLBACK_PROVIDER vacío = sin respaldo.
    LLM_FALLBACK_PROVIDER: str = ""
    LLM_FALLBACK_BASE_URL: str = "http://localhost:11434/v1"
    LLM_FALLBACK_API_KEY: SecretStr = SecretStr("ollama")
    LLM_FALLBACK_MODEL: str = "qwen3:8b"
    LLM_FALLBACK_REASONING_EFFORT: str = "none"
    LLM_FALLBACK_TIMEOUT: float = 60.0
    # Embeddings con endpoint propio: solo los usa la siembra de Chroma.
    EMBEDDING_BASE_URL: str = "http://localhost:11434/v1"
    EMBEDDING_API_KEY: SecretStr = SecretStr("ollama")
    EMBEDDING_MODEL: str = "nomic-embed-text"
    CHROMA_PERSIST_DIR: str = "./data/chroma"

    @field_validator("CORS_ORIGINS")
    @classmethod
    def _sin_comodin(cls, v: str) -> str:
        # La API no usa cookies (allow_credentials=False), pero un "*" igual abriría la
        # API a cualquier sitio. Lista explícita o nada; se falla al arrancar, no en silencio.
        if "*" in (o.strip() for o in v.split(",")):
            raise ValueError("CORS_ORIGINS no admite '*': lista los orígenes explícitos")
        return v

    @property
    def cors_origins(self) -> list[str]:
        # ponytail: CORS_ORIGINS es str y no list[str] porque pydantic-settings
        # exige formato JSON para tipos complejos y el .env usa CSV.
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
