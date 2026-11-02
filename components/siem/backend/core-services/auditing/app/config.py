
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))
AUDIT_DATABASE_URL = os.environ["AUDIT_DATABASE_URL"] if "AUDIT_DATABASE_URL" in os.environ else os.environ["DATABASE_URL"]
PSA_BASE_URL = "http://localhost:8001"
SERVICE_NAME = "auditing"
