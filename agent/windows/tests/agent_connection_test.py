"""Drive the real WinHTTP client against a loopback-only handshake and idle relay."""
import base64
import hashlib
import http.server
import subprocess
import sys
import threading


class Relay(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/stall":
            # The client deadline must expire before this handler sends any headers.
            self.server.finished.wait(12)
            return
        key = self.headers["Sec-WebSocket-Key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        self.send_response(101)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", base64.b64encode(hashlib.sha1(key.encode()).digest()).decode())
        self.end_headers()
        self.wfile.write(b"\x81\x02ok")
        self.rfile.read(2)
        self.wfile.write(b"\x88\x02\x03\xe8")
        self.close_connection = True


with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Relay) as server:
    server.finished = threading.Event()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        subprocess.run([sys.argv[1], str(server.server_port)], timeout=45, check=True)
    finally:
        server.finished.set()
        server.shutdown()
        thread.join()
