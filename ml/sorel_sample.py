"""Sample rows from the public SOREL-20M EMBER-v2 feature arrays without downloading them whole.

The .npz files on s3://sorel-20m are uncompressed zips, so each row of the
float32 (N, 2381) matrix can be fetched with an HTTP range request.

    python ml/sorel_sample.py train 600000 data/train      # ~5.7 GB download
    python ml/sorel_sample.py validation 50000 data/valid
    python ml/sorel_sample.py test 150000 data/test

Labels: 1 = malicious, 0 = benign (SOREL's is_malware).
"""

from __future__ import annotations

import argparse
import ast
import http.client
import struct
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np

BASE = "https://sorel-20m.s3.amazonaws.com/09-DEC-2020/lightGBM-features/"
DIM = 2381


def fetch(url: str, start: int, end: int, attempts: int = 5) -> bytes:
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"Range": f"bytes={start}-{end}"})
            with urllib.request.urlopen(req, timeout=120) as resp:
                data = resp.read()
            if len(data) == end - start + 1:
                return data
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(2 ** attempt)
    raise RuntimeError(f"range {start}-{end} failed")


def head_size(url: str) -> int:
    req = urllib.request.Request(url, method="HEAD")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return int(resp.headers["Content-Length"])


def members(url: str) -> dict[str, tuple[int, tuple, str]]:
    """Map npy member name -> (absolute data offset, shape, dtype)."""
    size = head_size(url)
    tail = fetch(url, size - 65536, size - 1)
    z64 = tail.rfind(b"PK\x06\x06")
    cd_size, cd_off = struct.unpack("<QQ", tail[z64 + 40:z64 + 56])
    cd = fetch(url, cd_off, cd_off + cd_size - 1)
    out, p = {}, 0
    while cd[p:p + 4] == b"PK\x01\x02":
        nl, el, cl = struct.unpack("<HHH", cd[p + 28:p + 34])
        lho = struct.unpack("<I", cd[p + 42:p + 46])[0]
        name = cd[p + 46:p + 46 + nl].decode()
        extra = cd[p + 46 + nl:p + 46 + nl + el]
        if lho == 0xFFFFFFFF:  # zip64 extra field: sizes come first if they were 0xFFFFFFFF
            fields = struct.unpack("<" + "Q" * ((len(extra) - 4) // 8), extra[4:4 + 8 * ((len(extra) - 4) // 8)])
            lho = fields[-1]
        local = fetch(url, lho, lho + 511)
        lnl, lel = struct.unpack("<HH", local[26:30])
        data_start = lho + 30 + lnl + lel
        header = fetch(url, data_start, data_start + 255)
        hlen = struct.unpack("<H", header[8:10])[0]
        meta = ast.literal_eval(header[10:10 + hlen].decode())
        out[name] = (data_start + 10 + hlen, meta["shape"], meta["descr"])
        p += 46 + nl + el + cl
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["train", "validation", "test"])
    ap.add_argument("rows", type=int)
    ap.add_argument("out")
    ap.add_argument("--block", type=int, default=1000, help="consecutive rows per request")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--workers", type=int, default=16)
    args = ap.parse_args()

    url = BASE + f"{args.split}-features.npz"
    info = members(url)
    x_off, (n, dim), _ = info["arr_0.npy"]
    y_off, _, y_dtype = info["arr_1.npy"]
    assert dim == DIM, dim
    y_all = np.frombuffer(fetch(url, y_off, y_off + n * np.dtype(y_dtype).itemsize - 1), dtype=y_dtype)

    rng = np.random.default_rng(args.seed)
    blocks = min(args.rows // args.block, n // args.block)
    starts = np.sort(rng.choice(n // args.block, size=blocks, replace=False)) * args.block
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    X = np.lib.format.open_memmap(out / "X.npy", mode="w+", dtype=np.float32, shape=(blocks * args.block, DIM))
    row_bytes = DIM * 4
    t0 = time.time()

    def grab(i_start):
        i, start = i_start
        raw = fetch(url, x_off + int(start) * row_bytes, x_off + (int(start) + args.block) * row_bytes - 1)
        X[i * args.block:(i + 1) * args.block] = np.frombuffer(raw, dtype=np.float32).reshape(args.block, DIM)
        return len(raw)

    done = 0
    with ThreadPoolExecutor(args.workers) as pool:
        for k, size in enumerate(pool.map(grab, enumerate(starts)), 1):
            done += size
            if k % 20 == 0 or k == blocks:
                rate = done / (time.time() - t0) / 1e6
                print(f"{k}/{blocks} blocks, {done / 1e9:.2f} GB, {rate:.1f} MB/s", file=sys.stderr, flush=True)
    X.flush()
    idx = (starts[:, None] + np.arange(args.block)[None, :]).ravel()
    np.save(out / "y.npy", y_all[idx].astype(np.int8))
    np.save(out / "rows.npy", idx)
    print(f"saved {len(idx)} rows; malicious share {float(y_all[idx].mean()):.3f}")


if __name__ == "__main__":
    main()
