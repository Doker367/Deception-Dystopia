#!/usr/bin/env python3
"""Build-time patch: serve a fingerprint beacon from the OpenCanary HTTP skin.

Only runs inside the pinned OpenCanary image. It adds a same-origin
``POST /__fp`` handler that logs the browser payload (and a bounded set of
client-hint headers) through ``factory.log``, and injects the beacon into the
``nasLogin`` skin. No attacker-controlled JavaScript is executed: the page
serves our own script only.
"""

from pathlib import Path

HTTP = Path("/usr/local/lib/python3.12/site-packages/opencanary/modules/http.py")
SKIN = Path("/usr/local/lib/python3.12/site-packages/opencanary/modules/data/http/skin/nasLogin/index.html")
FP_JS = Path("/tmp/fingerprint.js")

BRANCH = '''    def render_POST(self, request):
        if request.path == b"/__fp":
            try:
                raw = request.content.read(8192)
                headers = {}
                for name, values in request.requestHeaders.getAllRawHeaders():
                    key = name.decode("utf-8", "replace").lower()
                    if key in {"user-agent", "accept-language", "sec-ch-ua",
                               "sec-ch-ua-mobile", "sec-ch-ua-platform",
                               "device-memory", "downlink", "ect", "rtt", "save-data"}:
                        headers[key] = values[0].decode("utf-8", "replace")[:512]
                payload = {"client": raw.decode("utf-8", "replace"), "headers": headers}
                self.factory.log({"FINGERPRINT": json.dumps(payload, ensure_ascii=False)[:2000],
                                  "PATH": "/__fp", "METHOD": "POST"},
                                 transport=request.transport, logtype=3000)
            except Exception:
                pass
            request.setResponseCode(204)
            return b""
        try:
'''


def patch_http() -> None:
    source = HTTP.read_text(encoding="utf-8")
    if '"/__fp"' in source or "'/__fp'" in source:
        return
    if "import json" not in source:
        source = source.replace("import os\nimport re", "import json\nimport os\nimport re", 1)
    needle = "    def render_POST(self, request):\n        try:\n"
    if needle not in source:
        raise SystemExit("render_POST not found in OpenCanary HTTP module")
    HTTP.write_text(source.replace(needle, BRANCH, 1), encoding="utf-8")


def patch_skin() -> None:
    html = SKIN.read_text(encoding="utf-8")
    if "dystopia-fp" in html:
        return
    script = '<script id="dystopia-fp">' + FP_JS.read_text(encoding="utf-8") + "</script>"
    if "</body>" in html:
        html = html.replace("</body>", script + "</body>", 1)
    else:
        html += script
    SKIN.write_text(html, encoding="utf-8")


if __name__ == "__main__":
    patch_http()
    patch_skin()
