"""A self-contained, deliberately-vulnerable target for testing Beast403.

Single file, standard library only, runs on localhost. No Docker, no server.

    python mock_target.py            # serves on http://localhost:8403

Behaviour (the protected resource is /admin):
  GET /                              -> 200  public home page
  GET /admin                        -> 403  block page              (baseline oracle)
  GET /<random>                     -> 404  not-found page          (not-found oracle)

REAL bypasses (these should be REPORTED by Beast403):
  X-Forwarded-For: 127.0.0.1   on /admin   -> 200 admin panel
  X-Original-URL: /admin       on /        -> 200 admin panel
  GET /admin/                               -> 200 admin panel  (trailing slash)
  GET /admin/..;/                           -> 200 admin panel  (tomcat path-param)

FALSE-POSITIVE TRAP (this must NOT be reported -- the verifier should reject it):
  GET /admin%2f                             -> 200 but body is the BLOCK page
                                               (a soft block: 200 status, denial body)

Every request is logged with its RAW path, so you can also verify whether your
HTTP client preserved tricky paths like /admin/..;/ unchanged (the normalization
caveat from the README).
"""
from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PUBLIC = (
    "<html><head><title>Acme Home</title></head><body>"
    "<nav><a href='/'>home</a><a href='/about'>about</a></nav>"
    "<main><h1>Welcome to Acme</h1><p>Your trusted widget store.</p></main>"
    "<footer>(c) Acme</footer></body></html>"
)
BLOCK = (
    "<html><head><title>403 Forbidden</title></head><body>"
    "<h1>403 Forbidden</h1><p>Access denied. You don't have permission.</p>"
    "</body></html>"
)
NOTFOUND = (
    "<html><head><title>404 Not Found</title></head><body>"
    "<h1>404 Not Found</h1><p>The requested resource was not found.</p>"
    "</body></html>"
)
ADMIN = (
    "<html><head><title>Admin Panel</title></head><body>"
    "<nav><a href='/'>home</a><a href='/about'>about</a></nav>"
    "<h1>Admin Control Panel</h1>"
    "<table id='users'><tr><th>user</th><th>role</th></tr>"
    "<tr><td>alice</td><td>admin</td></tr><tr><td>bob</td><td>staff</td></tr></table>"
    "<div class='controls'><button>delete</button><button>reset</button>"
    "<button>grant</button></div></body></html>"
)


def _targets_admin(p: str) -> bool:
    return "admin" in p.lower().strip("/")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    # route EVERY HTTP method (incl. odd/lowercase verbs) through one handler
    def __getattr__(self, name):
        if name.startswith("do_"):
            return self._dispatch
        raise AttributeError(name)

    def _dispatch(self):
        status, body = self._decide()
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "Apache-Coyote/1.1")  # => fingerprint sees Tomcat
        self.end_headers()
        if self.command.upper() != "HEAD":
            self.wfile.write(data)

    def _decide(self) -> tuple[int, str]:
        base = self.path.split("?", 1)[0].split("#", 1)[0]
        h = {k.lower(): v for k, v in self.headers.items()}
        rewrite = h.get("x-original-url", "") or h.get("x-rewrite-url", "")
        about_admin = _targets_admin(base) or _targets_admin(rewrite)

        if not about_admin:
            if base in ("/", "/index.html", ""):
                return 200, PUBLIC
            return 404, NOTFOUND

        # soft-block trap: looks like a 200 win but is really a denial
        if "admin%2f" in base.lower():
            return 200, BLOCK

        xff = h.get("x-forwarded-for", "")
        bypass = (
            "127.0.0.1" in xff
            or h.get("x-real-ip", "").startswith("127.")
            or _targets_admin(rewrite)          # X-Original-URL: /admin while path=/
            or base.rstrip("/").lower().endswith("/admin") and base.endswith("/")
            or "..;/" in base
        )
        return (200, ADMIN) if bypass else (403, BLOCK)

    def log_message(self, fmt, *args):
        # concise: show the RAW path actually received (useful for the
        # path-normalization check)
        sys.stderr.write(f"  <- {self.command} {self.path}\n")


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8403
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"[mock_target] listening on http://localhost:{port}  (Ctrl-C to stop)")
    print(f"[mock_target] try:  python -m beast403.cli http://localhost:{port} /admin")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[mock_target] bye")


if __name__ == "__main__":
    main()
