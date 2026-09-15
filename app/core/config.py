from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración centralizada, leída desde .env."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    LLM_API_KEY: str = ""
    REPUTATION_API_KEY: str = ""
    CORS_ORIGINS: str = ""

    @property
    def cors_origins(self) -> list[str]:
        # ponytail: CORS_ORIGINS es str y no list[str] porque pydantic-settings
        # exige formato JSON para tipos complejos y el .env usa CSV.
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()
