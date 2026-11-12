"""Windows CI: run the real DNS proxy (fenrir-dnsproxy-smoke.exe) against a stand-in for Fenrir's DoH endpoint.

Checks UDP and TCP answers, truncation, remembered blocks, internal names going to the network's DNS, fail-open and
fail-closed behaviour, and that the agent's NRPT rule really sends Windows lookups to the proxy and is removed cleanly.
Needs an elevated prompt (port 53 and the NRPT). Usage: python dns_proxy_smoke.py path\\to\\fenrir-dnsproxy-smoke.exe
"""
import socket
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXE = sys.argv[1]
PROXY = ("127.77.0.53", 53)
SEEN: list[str] = []


def qname(message: bytes) -> tuple[str, int, int]:
    labels, i = [], 12
    while message[i]:
        labels.append(message[i + 1:i + 1 + message[i]].decode())
        i += 1 + message[i]
    return ".".join(labels).lower(), struct.unpack(">H", message[i + 1:i + 3])[0], i + 5


def answer(query: bytes, addresses: list[str], rcode: int = 0) -> bytes:
    _, _, end = qname(query)
    out = query[:2] + struct.pack(">BBHHHH", 0x81, 0x80 | rcode, 1, len(addresses), 0, 0) + query[12:end]
    for address in addresses:
        out += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    return out


class DoH(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers["Content-Length"]))
        name, qtype, _ = qname(body)
        SEEN.append(name)
        action = "block" if name.startswith("blocked.") else "allow"
        if qtype != 1:
            reply = answer(body, [])
        elif action == "block":
            reply = answer(body, ["0.0.0.0"])
        elif name.startswith("big."):
            reply = answer(body, [f"192.0.2.{i}" for i in range(1, 60)])
        else:
            reply = answer(body, ["192.0.2.10"])
        self.send_response(200)
        self.send_header("Content-Type", "application/dns-message")
        self.send_header("X-Fenrir-Dns-Action", action)
        self.send_header("X-Fenrir-Dns-Reason", "test-category" if action == "block" else "")
        self.send_header("Content-Length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def log_message(self, *args):
        pass


def query(name: str, qtype: int = 1, tcp: bool = False, query_id: int = 0x4242) -> bytes:
    message = struct.pack(">HBBHHHH", query_id, 1, 0, 1, 0, 0, 0)
    for label in name.split("."):
        message += bytes([len(label)]) + label.encode()
    message += b"\x00" + struct.pack(">HH", qtype, 1)
    if tcp:
        with socket.create_connection(PROXY, timeout=10) as s:
            s.sendall(struct.pack(">H", len(message)) + message)
            size = struct.unpack(">H", s.recv(2))[0]
            data = b""
            while len(data) < size:
                data += s.recv(size - len(data))
            return data
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(10)
        s.sendto(message, PROXY)
        return s.recv(4096)


def rcode(reply: bytes) -> int:
    return reply[3] & 0x0F


def answers(reply: bytes) -> int:
    return struct.unpack(">H", reply[6:8])[0]


def check(condition: bool, what: str) -> None:
    print(("PASS " if condition else "FAIL ") + what, flush=True)
    if not condition:
        raise SystemExit(1)


def serve(url: str, seconds: int, mode: str = "open") -> subprocess.Popen:
    process = subprocess.Popen([EXE, "serve", url, str(seconds), mode], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    line = process.stdout.readline()
    check("ready" in line, f"proxy started ({mode}): {line.strip()}")
    return process


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([EXE, *args], capture_output=True, text=True, timeout=120)


def main() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 8053), DoH)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = "http://127.0.0.1:8053/dns/test-token/dns-query"

    proxy = serve(url, 25)
    check(run("probe").returncode == 0, "health probe answered")
    reply = query("allowed.fenrir-test")
    check(rcode(reply) == 0 and answers(reply) == 1 and reply[-4:] == socket.inet_aton("192.0.2.10"), "UDP lookup answered by the cloud")
    check(reply[:2] == b"\x42\x42", "transaction ID preserved")
    reply = query("allowed.fenrir-test", tcp=True, query_id=0x1111)
    check(rcode(reply) == 0 and reply[:2] == b"\x11\x11", "TCP lookup answered (cached answer, new ID)")
    check(SEEN.count("allowed.fenrir-test") == 1, "repeat lookups served from the answer cache")
    reply = query("big.fenrir-test")
    check(reply[2] & 0x02 and answers(reply) == 0, "oversized UDP reply truncated (TC)")
    reply = query("big.fenrir-test", tcp=True)
    check(answers(reply) == 59, "full answer over TCP")
    first = query("blocked.fenrir-test")
    second = query("blocked.fenrir-test")
    check(first[-4:] == b"\x00\x00\x00\x00" and second[-4:] == b"\x00\x00\x00\x00", "blocked name answered 0.0.0.0")
    check(SEEN.count("blocked.fenrir-test") == 1, "second lookup answered from the remembered block")
    before = len(SEEN)
    query("printer.corp.fenrir-test")
    query("fileserver")
    query("4.3.2.10.in-addr.arpa", qtype=12)
    check(len(SEEN) == before, "internal names never sent to the cloud")

    # The NRPT rule: Windows lookups now go through the proxy.
    applied = run("apply-rule")
    print(applied.stdout.strip(), applied.stderr.strip())
    check(applied.returncode == 0, "NRPT rule applied")
    rules = subprocess.run(["powershell", "-NoProfile", "-Command",
                            "(Get-DnsClientNrptRule | Where-Object Comment -eq 'Fenrir DNS protection' | Measure-Object).Count"],
                           capture_output=True, text=True).stdout.strip()
    check(rules == "1", "exactly one Fenrir NRPT rule")
    seen_before = len(SEEN)
    resolved = socket.gethostbyname("nrpt-check.fenrir-test")
    check(resolved == "192.0.2.10" and len(SEEN) > seen_before, "Windows resolves through the proxy via the NRPT rule")
    removed = run("remove-rule")
    print(removed.stdout.strip())
    check(removed.returncode == 0 and '"removed":1' in removed.stdout.replace(" ", ""), "NRPT rule removed")
    output = proxy.communicate(timeout=60)[0]
    print(output.strip())

    # Fenrir unreachable: fail open uses the network's DNS, fail closed refuses.
    dead = "http://127.0.0.1:9/dns/test-token/dns-query"
    proxy = serve(dead, 12, "open")
    reply = query("www.microsoft.com")
    check(rcode(reply) == 0 and answers(reply) > 0, "fail open: answered by the network's DNS")
    proxy.communicate(timeout=60)
    proxy = serve(dead, 8, "closed")
    check(rcode(query("www.microsoft.com")) == 5, "fail closed: refused")
    proxy.communicate(timeout=60)
    server.shutdown()
    print("DNS proxy smoke test passed.")


if __name__ == "__main__":
    try:
        main()
    finally:
        subprocess.run([EXE, "remove-rule"], capture_output=True, text=True, timeout=120)
