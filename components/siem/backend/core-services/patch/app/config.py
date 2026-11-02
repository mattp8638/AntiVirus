
import os
from dotenv import load_dotenv
from dataclasses import dataclass
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))
PATCH_DATABASE_URL = os.environ["PATCH_DATABASE_URL"] if "PATCH_DATABASE_URL" in os.environ else os.environ["DATABASE_URL"]

@dataclass(frozen=True)
class Settings:
	environment: str
	service_name: str
	api_key: str
	storage_path: str
	max_log_bytes: int
	max_patches_per_batch: int

def load_settings() -> Settings:
	return Settings(
		environment=os.environ.get("PATCH_ENV", "development"),
		service_name=os.environ.get("PATCH_SERVICE_NAME", "patch-service"),
		api_key=os.environ.get("PATCH_API_KEY", ""),
		storage_path=os.environ.get("PATCH_STORAGE_PATH", "data/patch-engine.json"),
		max_log_bytes=int(os.environ.get("PATCH_MAX_LOG_BYTES", "8192")),
		max_patches_per_batch=int(os.environ.get("PATCH_MAX_PATCHES_PER_BATCH", "250")),
	)
