"""
VulnPrioritizer Configuration
Centralized settings management with environment variable support.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator
from typing import Optional, List, Union
import os


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )
    
    # App Settings
    app_name: str = "VulnPrioritizer"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # API Settings
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    
    # Database
    database_url: str = "sqlite+aiosqlite:///./data/vulnprioritizer.db"
    
    # NVD API
    nvd_api_key: Optional[str] = None
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Gemini AI
    gemini_api_key: Optional[str] = None
    gemini_model: str = "gemini-pro"
    
    # ML Model
    model_path: str = "./models/rf_classifier.joblib"
    min_f1_score: float = 0.92
    
    # CORS (for React frontend)
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    
    @property
    def cors_origins_list(self) -> List[str]:
        """Parse CORS origins from comma-separated string."""
        return [origin.strip() for origin in self.cors_origins.split(",")]


settings = Settings()


