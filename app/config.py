from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional
import os

class Settings(BaseSettings):
    SECRET_KEY: str
    SECURE_COOKIES: bool = True
    DATABASE_URL: str = "sqlite:///./app.db"
    RATE_LIMIT_BACKEND: Optional[str] = None  # e.g., 'redis://localhost:6379/0'

    model_config = ConfigDict(
        env_file = os.path.join(os.path.dirname(__file__), "..", ".env"),
        env_file_encoding = "utf-8"
    )

settings = Settings()
