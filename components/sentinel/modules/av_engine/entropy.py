import math
from pathlib import Path


def shannon_entropy(path: Path, max_bytes: int = 2 * 1024 * 1024) -> float:
    data = path.read_bytes()[:max_bytes]
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)
