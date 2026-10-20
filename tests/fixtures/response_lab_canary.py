"""Fixed traffic probes for disposable response acceptance networks only."""
import http.server
import socket
import subprocess
import sys

if sys.argv[1] == "client":
    routes = (("198.19.0.0/24", "198.18.0.10"), ("2001:db8:198:19::/64", "2001:db8:198:18::10"))
else:
    routes = (("198.18.0.0/24", "198.19.0.10"), ("2001:db8:198:18::/64", "2001:db8:198:19::10"))
for network, gateway in routes:
    subprocess.run(["/usr/sbin/ip", "-6" if ":" in network else "-4", "route", "add", network, "via", gateway], check=True)


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        status = 200
        if self.path in {"/probe/ipv4", "/probe/ipv6"}:
            address = "198.19.0.20" if self.path.endswith("ipv4") else "2001:db8:198:19::20"
            try:
                with socket.create_connection((address, 8000), timeout=1):
                    pass
            except OSError:
                status = 503
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6


Server(("::", 8000), Handler).serve_forever()
