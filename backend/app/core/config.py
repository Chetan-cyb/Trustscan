from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    database_url: str = "sqlite:///./trustscan.db"
    upload_dir: str = "./uploads"
    max_upload_bytes: int = 50 * 1024 * 1024
    allowed_extension: str = ".apk"
    cors_origins: str = "*"


settings = Settings()
