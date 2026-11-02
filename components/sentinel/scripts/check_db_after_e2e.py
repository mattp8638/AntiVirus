from modules import storage
from pprint import pprint

AGENT_ID = "b69708b6-374f-43a7-94a0-1748b303ca3a"

print("DB path:", storage.DB_PATH)
print("Latest evidence:")
pprint(storage.get_latest_evidence(AGENT_ID))
print("Investigation requests:")
pprint(storage.list_investigation_requests())
print("Investigation results:")
pprint(storage.list_investigation_results())
