
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env'))
PENETRATION_DATABASE_URL = os.environ["PENETRATION_DATABASE_URL"] if "PENETRATION_DATABASE_URL" in os.environ else os.environ["DATABASE_URL"]
