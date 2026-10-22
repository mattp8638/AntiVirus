import os
from dotenv import load_dotenv
from dataclasses import dataclass
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))
IDENTITY_DATABASE_URL = os.environ["IDENTITY_DATABASE_URL"] if "IDENTITY_DATABASE_URL" in os.environ else os.environ["DATABASE_URL"]

@dataclass(frozen=True)
class Settings:
	environment: str
	hmac_shared_key: str
	signature_ttl_seconds: int
	service_name: str
	heartbeat_offline_threshold_seconds: int
	tasks_enabled: bool
	task_allowlist_patterns: tuple[str, ...]
	task_max_payload_bytes: int
	task_max_output_bytes: int
	task_max_ttl_seconds: int
	tasks_disabled_tenants: tuple[str, ...]
	tasks_disabled_assets: tuple[str, ...]
	dev_seed_enabled: bool

def load_settings() -> Settings:
	allowlist = tuple(
		pattern.strip()
		for pattern in os.environ.get("IDENTITY_TASK_ALLOWLIST", "").split(",")
		if pattern.strip()
	)
	disabled_tenants = tuple(
		tenant.strip()
		for tenant in os.environ.get("IDENTITY_TASKS_DISABLED_TENANTS", "").split(",")
		if tenant.strip()
	)
	disabled_assets = tuple(
		asset.strip()
		for asset in os.environ.get("IDENTITY_TASKS_DISABLED_ASSETS", "").split(",")
		if asset.strip()
	)
	return Settings(
		environment=os.environ.get("IDENTITY_ENV", "development"),
		hmac_shared_key=os.environ.get("IDENTITY_HMAC_SHARED_KEY", ""),
		signature_ttl_seconds=int(os.environ.get("IDENTITY_SIGNATURE_TTL", "120")),
		service_name=os.environ.get("IDENTITY_SERVICE_NAME", "identity-service"),
		heartbeat_offline_threshold_seconds=int(
			os.environ.get("IDENTITY_OFFLINE_THRESHOLD", "120")
		),
		tasks_enabled=os.environ.get("IDENTITY_TASKS_ENABLED", "false").lower() == "true",
		task_allowlist_patterns=allowlist,
		task_max_payload_bytes=int(os.environ.get("IDENTITY_TASK_MAX_PAYLOAD", "4096")),
		task_max_output_bytes=int(os.environ.get("IDENTITY_TASK_MAX_OUTPUT", "8192")),
		task_max_ttl_seconds=int(os.environ.get("IDENTITY_TASK_MAX_TTL", "900")),
		tasks_disabled_tenants=disabled_tenants,
		tasks_disabled_assets=disabled_assets,
		dev_seed_enabled=os.environ.get("IDENTITY_DEV_SEED", "false").lower() == "true",
	)
