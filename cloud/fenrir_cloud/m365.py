"""Bounded, read-only Microsoft Graph v1.0 synchronisation."""
from urllib.parse import urlparse
import httpx
from time import monotonic
from . import crypto

GRAPH = "https://graph.microsoft.com/v1.0"

def collect(client, url, token, deadline=None):
    deadline = deadline if deadline is not None else monotonic() + 120
    rows, seen = [], set()
    while url:
        if monotonic() >= deadline:
            raise ValueError("Graph synchronization exceeded its time budget")
        parsed = urlparse(url)
        if parsed.scheme != "https" or parsed.netloc != "graph.microsoft.com" or not parsed.path.startswith("/v1.0/"):
            raise ValueError("Graph returned an invalid pagination URL")
        if url in seen or len(seen) >= 100:
            raise ValueError("Graph pagination exceeded its safety limit")
        seen.add(url)
        response = client.get(url, headers={"Authorization": "Bearer " + token})
        response.raise_for_status()
        data = response.json()
        page = data.get("value")
        if not isinstance(page, list) or not all(isinstance(row, dict) for row in page):
            raise ValueError("Invalid Graph response")
        rows.extend(page)
        if len(rows) > 50000:
            raise ValueError("Graph response exceeds 50000 records")
        url = data.get("@odata.nextLink")
    return rows

def synchronize(connection):
    deadline = monotonic() + 120
    with httpx.Client(timeout=20, follow_redirects=False) as client:
        token = access_token(client, connection)
        return {
            "users": collect(client, GRAPH + "/users?$select=id,displayName,userPrincipalName,accountEnabled,assignedLicenses&$top=999", token, deadline),
            "licenses": collect(client, GRAPH + "/subscribedSkus", token, deadline),
            "secureScores": collect(client, GRAPH + "/security/secureScores?$top=1", token, deadline),
        }


def access_token(client, connection):
    secret = crypto.decrypt(connection.credentials_envelope, f"m365:{connection.tenant_id}:{connection.id}")
    response = client.post(f"https://login.microsoftonline.com/{connection.directory_id}/oauth2/v2.0/token",
        data={"client_id": connection.client_id, "client_secret": secret,
              "grant_type": "client_credentials", "scope": "https://graph.microsoft.com/.default"})
    response.raise_for_status()
    return response.json()["access_token"]
