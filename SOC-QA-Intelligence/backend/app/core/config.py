import os
from pathlib import Path
from pydantic import BaseModel

ROOT_DIR = Path(__file__).resolve().parents[3]


class Settings(BaseModel):
    app_name: str = os.getenv("APP_NAME", "SOC-QA Intelligence")
    app_version: str = os.getenv("APP_VERSION", "1.0.0-research")
    api_prefix: str = os.getenv("API_PREFIX", "/api/v1")
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql://socqa_user:socqa_research_pass@localhost:5432/socqa_intelligence",
    )
    sqlite_path: str = os.getenv(
        "SQLITE_FALLBACK_PATH", str(ROOT_DIR / "data" / "socqa_research.db")
    )
    use_sqlite_fallback: bool = os.getenv("USE_SQLITE_FALLBACK", "true").lower() == "true"
    max_upload_size_bytes: int = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", str(50 * 1024 * 1024)))
    allowed_extensions: tuple = (".csv", ".json", ".jsonl", ".ndjson", ".xes")
    raw_storage_dir: Path = Path(os.getenv("RAW_STORAGE_DIR", str(ROOT_DIR / "data" / "raw")))
    normalized_storage_dir: Path = Path(
        os.getenv("NORMALIZED_STORAGE_DIR", str(ROOT_DIR / "data" / "normalized"))
    )
    export_storage_dir: Path = Path(
        os.getenv("EXPORT_STORAGE_DIR", str(ROOT_DIR / "data" / "exports"))
    )
    ai_module_enabled: bool = os.getenv("AI_MODULE_ENABLED", "false").lower() == "true"
    ai_provider: str = os.getenv("AI_PROVIDER", "disabled")
    ai_model_name: str = os.getenv("AI_MODEL_NAME", "none")
    ai_prompt_version: str = os.getenv("AI_PROMPT_VERSION", "v1.0-audit-strict")


settings = Settings()
for folder in (
    settings.raw_storage_dir,
    settings.normalized_storage_dir,
    settings.export_storage_dir,
):
    folder.mkdir(parents=True, exist_ok=True)
