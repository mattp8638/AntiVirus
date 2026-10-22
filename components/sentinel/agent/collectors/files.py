import os
import hashlib
from datetime import datetime, timedelta

TARGET_DIRS = [
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
    os.environ.get("TEMP", "")
]


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def collect_recent_files(hours=24):
    results = []
    cutoff = datetime.now() - timedelta(hours=hours)

    for directory in TARGET_DIRS:
        if not directory or not os.path.exists(directory):
            continue

        for root, _, files in os.walk(directory):
            for f in files:
                path = os.path.join(root, f)
                try:
                    mtime = datetime.fromtimestamp(os.path.getmtime(path))
                    if mtime > cutoff:
                        results.append({
                            "path": path,
                            "modified": mtime.isoformat(),
                            "hash": sha256_file(path)
                        })
                except Exception:
                    continue

    return results
