"""The governance dashboard: a server that implements GET, and nothing else.

The spec requires that "no dashboard action can change a finding's status: status
changes only happen through the approval/validation workflow". The way to be certain
of that is not to disable the other verbs — it is to never write them. There is no
`do_POST` in this file. A POST gets 501 from the standard library because nothing
here handles one.

It binds to 127.0.0.1 only. `dsh web`, the DeepSeek harness's UI, shipped a full
agent control plane over an unauthenticated loopback HTTP server and that turned into
a local-process RCE (their Discussion #853). Loopback is not an authorization
boundary. This server is safe for a different reason: the worst a caller can do is
read a run they already have on disk.

    harness serve --run R-...        then open http://127.0.0.1:8711
"""

from __future__ import annotations

import http.server
import json
import os
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))


def _payload(store) -> dict:
    """Everything the page renders, assembled once per request from the run directory."""
    def read_json(path, default):
        return json.load(open(path, encoding="utf-8")) if os.path.exists(path) else default

    return {
        "metrics": read_json(store.metrics, {}),
        "clusters": read_json(store.clusters, {"clusters": {}}),
        "findings": store.read_all(),
        "audit": list(store.audit_entries()),
        "run": os.path.basename(store.root),
    }


def serve(store, port: int = 8711, open_browser: bool = True) -> None:
    index = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()

    class Handler(http.server.BaseHTTPRequestHandler):
        # Note what is absent: do_POST, do_PUT, do_DELETE, do_PATCH.
        def do_GET(self):                                    # noqa: N802
            if self.path.startswith("/data.json"):
                body = json.dumps(_payload(store)).encode("utf-8")
                ctype = "application/json"
            else:
                body = index.encode("utf-8")
                ctype = "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):                           # keep the console readable
            pass

    url = f"http://127.0.0.1:{port}/"
    print(f"dashboard for {os.path.basename(store.root)} at {url}  (read-only; ctrl-c to stop)")
    if open_browser:
        webbrowser.open(url)
    http.server.HTTPServer(("127.0.0.1", port), Handler).serve_forever()
