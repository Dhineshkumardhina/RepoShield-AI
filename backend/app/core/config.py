"""Environment-variable configuration using Pydantic Settings."""
from typing import List, Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    # Core Application Metadata
    APP_NAME: str = "RepoShield AI"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"  # development, staging, production
    DEBUG: bool = True
    ORGANIZATION: str = "Xerova Digital Solutions"

    # API Routing
    API_V1_PREFIX: str = "/api/v1"

    # Server Host & Port (Default to localhost; set HOST=0.0.0.0 in container deployments)
    HOST: str = "127.0.0.1"
    PORT: int = 8000

    # Database Configuration (SQLite default for local dev, PostgreSQL for production)
    DATABASE_URL: str = "sqlite:///./reposhield.db"

    # CORS Allowed Origins
    CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # Structured Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT_JSON: bool = False

    # Security Secret & Cryptography (Must be overridden in production)
    SECRET_KEY: str = "dev-insecure-secret-key-32-chars-long!!"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours for developer convenience
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Cookie Session Configuration
    COOKIE_NAME: str = "access_token"
    COOKIE_SAMESITE: str = "lax"  # "lax" or "strict"
    COOKIE_HTTPONLY: bool = True

    # AI Security Analyst Configuration (Gemini API)
    GEMINI_API_KEY: Optional[str] = None
    GEMINI_MODEL: str = "gemini-2.5-flash"
    AI_TIMEOUT_SECONDS: int = 15
    AI_MAX_RETRIES: int = 2


    # Repository Ingestion & Workspace Hardening Settings
    WORKSPACE_ROOT: str = "data/workspaces"
    MAX_UPLOAD_SIZE_BYTES: int = 50 * 1024 * 1024  # 50 MB max zip upload
    MAX_EXTRACTED_SIZE_BYTES: int = 200 * 1024 * 1024  # 200 MB max uncompressed expansion
    MAX_FILE_COUNT: int = 5000  # Max files allowed in archive
    MAX_COMPRESSION_RATIO: float = 100.0  # Zip bomb detection threshold
    MAX_SINGLE_FILE_BYTES: int = 10 * 1024 * 1024  # 10 MB per file limit
    GIT_CLONE_TIMEOUT_SECONDS: int = 60  # Git clone timeout
    ALLOW_PRIVATE_NETWORKS: bool = False  # SSRF protection: block private/cloud IPs

    # Operational Safety & Concurrency Limits
    DOCS_ENABLED: bool = True
    MAX_CONCURRENT_SCANS_PER_USER: int = 3
    MAX_DAILY_SCANS_PER_USER: int = 100
    MAX_CONCURRENT_VERIFICATIONS_PER_USER: int = 3
    MAX_REQUEST_BODY_SIZE_BYTES: int = 60 * 1024 * 1024  # 60 MB maximum raw HTTP request body
    STALE_JOB_TIMEOUT_MINUTES: int = 15

    @property
    def cookie_secure(self) -> bool:
        """Enforce HTTPS cookie secure flag in production."""
        return self.is_production

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["*"]

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() == "production"

    @property
    def is_staging(self) -> bool:
        return self.APP_ENV.lower() == "staging"

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str, info) -> str:
        # Prevent SQLite from being used in production
        env = info.data.get("APP_ENV", "development")
        if env.lower() == "production" and v.startswith("sqlite"):
            raise ValueError("SQLite cannot be used in production. Configure a PostgreSQL DATABASE_URL.")
        return v

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        env = info.data.get("APP_ENV", "development")
        if env.lower() == "production":
            if "dev-insecure" in v or "replace-in-production" in v or len(v) < 32:
                raise ValueError(
                    "Production deployment requires a cryptographically strong SECRET_KEY (minimum 32 characters, no development defaults)."
                )
        return v


settings = Settings()
