
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))
DATABASE_URL = os.environ["DATABASE_URL"]
SERVICE_NAME = "siem"
