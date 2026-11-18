"""Trampa HTTP: exposición configurable y captura de datos del atacante.

Cubre la cadena completa sin contenedores ni red real:

1. El compose publica UN solo puerto HTTP (la trampa) con
   ``DYSTOPIA_HTTP_TRAP_PORT``/``DYSTOPIA_HTTP_TRAP_BIND``; nunca 80/443 ni
   otros puertos de honeypots.
2. El shim de acceso (``docker/deception/opencanary/access_shim.py``) convierte
   cada línea de acceso de Twisted en un registro con ip/método/ruta/UA/
   referer/estado, y el normalizador lo lleva a un evento ``http_request``.
3. El parche del módulo HTTP (``patch_http_capture.py``) se aplica sobre el
   código real de opencanary 0.9.10 y registra las credenciales Basic; el
   normalizador las lleva a ``detail.credentials`` (§12 fase 7) junto con
   ``auth``, ``src_port``, método, path y user-agent.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from runtime.normalize import normalize_raw  # noqa: E402


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def shim():
    """El access_shim del contenedor OpenCanary (solo stdlib)."""
    return _load("access_shim", REPO / "docker/deception/opencanary/access_shim.py")


@pytest.fixture(scope="module")
def patch_http_capture():
    return _load(
        "patch_http_capture",
        REPO / "docker/deception/opencanary/patch_http_capture.py",
    )


# ── 1. Exposición configurable (compose + .env.example) ─────────────────


def test_compose_publishes_only_the_configurable_http_trap():
    compose = yaml.safe_load((REPO / "deploy/local/docker-compose.yml").read_text())
    opencanary = compose["services"]["opencanary"]
    traps = [p for p in opencanary["ports"] if p.endswith(":80/tcp")]
    # Un único puerto HTTP, referido por las dos variables con sus defectos.
    assert traps == [
        "${DYSTOPIA_HTTP_TRAP_BIND:-127.0.0.1}:${DYSTOPIA_HTTP_TRAP_PORT:-8080}:80/tcp"
    ]
    # Ningún servicio publica 80/443 en el host; el resto sigue en loopback.
    for name, service in compose["services"].items():
        for mapping in service.get("ports", []):
            if "${" in mapping:
                continue
            host_port = int(mapping.split(":")[-2])
            assert host_port not in (80, 443), name
            assert mapping.startswith("127.0.0.1:"), name


def test_env_example_documents_the_trap_variables():
    example = (REPO / "deploy/local/.env.example").read_text()
    assert "DYSTOPIA_HTTP_TRAP_PORT=8080" in example
    assert "DYSTOPIA_HTTP_TRAP_BIND=10.66.0.3" in example
    # La regla ufw exacta queda documentada (la aplica el operador).
    assert "ufw allow from any to 10.66.0.3 port 8080 proto tcp" in example


# ── 2. Cada petición HTTP deja evento (línea de acceso de Twisted) ──────


LINE = (
    '203.0.113.7 - - [17/Nov/2026:10:00:00 +0000] '
    '"GET /admin?action=import HTTP/1.1" 404 153 '
    '"http://ref.example/scan" "python-requests/2.31.0"'
)


def test_access_shim_captures_request_fields(shim):
    record = shim.access_record(LINE)
    assert record is not None
    assert record["src_host"] == "203.0.113.7"
    assert record["dst_port"] == 80
    assert record["logtype"] == 3000
    logdata = record["logdata"]
    assert logdata["METHOD"] == "GET"
    assert logdata["PATH"] == "/admin?action=import"
    assert logdata["STATUS"] == "404"
    assert logdata["USERAGENT"] == "python-requests/2.31.0"
    assert logdata["REFERER"] == "http://ref.example/scan"
    # El formato NCSA no trae puerto de origen ni cabeceras: -1 y el
    # normalizador lo omite (esos campos llegan por los eventos JSON del módulo).
    assert record["src_port"] == -1


def test_access_shim_ignores_non_access_lines_and_fingerprint(shim):
    assert shim.access_record("127.0.0.1 - - [x] malformed") is None
    assert shim.access_record('{"logtype": 4002, "msg": "login"}') is None
    fingerprint = ('203.0.113.7 - - [17/Nov/2026:10:00:00 +0000] '
                   '"POST /__fp HTTP/1.1" 204 0 "-" "curl/8.5.0"')
    assert shim.access_record(fingerprint) is None  # lo registra el handler /__fp


def test_http_access_line_becomes_http_request_event(shim):
    record = shim.access_record(LINE)
    event = normalize_raw("opencanary", "sw-access-01", record)
    assert event["type"] == "http_request"
    assert event["proto"] == "http"
    assert event["src_ip"] == "203.0.113.7"
    assert "src_port" not in event  # -1 descartado por el contrato
    detail = event["detail"]
    assert detail["method"] == "GET"
    assert detail["path"] == "/admin?action=import"
    assert detail["status"] == "404"
    assert detail["useragent"] == "python-requests/2.31.0"
    assert detail["referer"] == "http://ref.example/scan"
    assert detail["mitre"] == "T1190"


# ── 3. El parche captura credenciales Basic sobre el módulo real ────────
#
# Fragmentos VERBATIM del http.py de opencanary==0.9.10 (rueda PyPI); son los
# anclajes sobre los que opera patch_http_capture.py dentro de la imagen.

_OPENCANARY_0910 = '''
class CanaryRequest(Request):
    allowedMethods = [
        "GET",
        "POST",
        "DELETE",
        "PATCH",
        "PUT",
        "CONNECT",
        "TRACE",
        "HEAD",
    ]

    def process(self):
        if self.method.decode("utf-8") not in self.allowedMethods:
            self.transport.write(b"HTTP/1.1 405 Method Not Allowed\\r\\n\\r\\n")
            self.length = None
            self.transport.loseConnection()
            return
        Request.process(self)


class BasicLogin(Resource):
    def render_GET(self, request, loginFailed=False):
        if not loginFailed:
            useragent = request.getHeader("user-agent")
            if not useragent:
                useragent = "<not supplied>"

            logdata = {
                "SKIN": self.skin,
                "HOSTNAME": request.getRequestHostname(),
                "PATH": request.path,
                "USERAGENT": useragent,
            }

            logtype = self.factory.logger.LOG_HTTP_GET
            self.factory.log(logdata, transport=request.transport, logtype=logtype)

        return self.login.encode()

    def render_POST(self, request):
        try:
            username = request.args[b"username"][0]
        except (KeyError, IndexError):
            username = "<not supplied>"
        try:
            password = request.args[b"password"][0]
        except (KeyError, IndexError):
            password = "<not supplied>"
        useragent = request.getHeader(b"user-agent")
        if not useragent:
            useragent = "<not supplied>"

        logdata = {
            "USERNAME": username,
            "PASSWORD": password,
            "SKIN": self.skin,
            "HOSTNAME": request.getRequestHostname(),
            "PATH": request.path,
            "USERAGENT": useragent,
        }
        logtype = self.factory.logger.LOG_HTTP_POST_LOGIN_ATTEMPT
        self.factory.log(logdata, transport=request.transport, logtype=logtype)

        return self.err.encode()


class CanaryHTTP(CanaryService):
    def getService(self):
        page = BasicLogin(factory=self)
        root = StaticNoDirListing(self.staticdir)
        root.createErrorPages(self)
        root.putChild(b"", RedirectCustomHeaders(b"/index.html", factory=self))
        root.putChild(b"index.html", page)
        wrapped = EncodingResourceWrapper(root, [GzipEncoderFactory()])
        site = CanaryHttpServiceSite(wrapped)
        return internet.TCPServer(self.port, site, interface=self.listen_addr)
'''


@pytest.fixture()
def patched_source(tmp_path, patch_http_capture):
    module = tmp_path / "http.py"
    module.write_text(_OPENCANARY_0910)
    patch_http_capture.patch_http(module)
    patch_http_capture.patch_http(module)  # idempotente
    return module.read_text()


def test_patch_applies_to_real_opencanary_module_and_compiles(patched_source):
    compile(patched_source, "http_patched.py", "exec")
    assert "_dystopia_log_basic" in patched_source
    assert 'site.dystopia_factory = self' in patched_source
    # La captura Basic pasa al inicio de process() (cubre 404 y cualquier ruta).
    basic_probe = 'auth.lower().startswith("basic ")'
    assert basic_probe in patched_source
    assert patched_source.index(basic_probe) < patched_source.index("not in self.allowedMethods")


def test_patched_render_logs_method_and_referer(patched_source):
    assert '"METHOD": "GET"' in patched_source
    assert '"METHOD": "POST"' in patched_source
    assert 'logdata["REFERER"]' in patched_source


def test_normalized_basic_auth_records_credentials():
    """Registro tal cual emite el módulo parcheado ante Basic auth."""
    raw = {
        "logtype": 3001,
        "logdata": {
            "USERNAME": "admin",
            "PASSWORD": "S3cret-Pa55",
            "AUTH": "basic",
            "SKIN": "nasLogin",
            "HOSTNAME": "10.66.0.3",
            "PATH": "/admin",
            "METHOD": "GET",
            "USERAGENT": "python-requests/2.31",
        },
        "src_host": "198.51.100.7",
        "src_port": 55012,
        "dst_host": "10.66.0.3",
        "dst_port": 80,
        "msg": "Basic auth attempt",
        "utc_time": "2026-11-17 10:00:00.000000",
    }
    event = normalize_raw("opencanary", "sw-access-01", raw)
    assert event["type"] == "login_attempt"
    assert event["proto"] == "http"
    assert event["src_ip"] == "198.51.100.7"
    assert event["src_port"] == 55012
    assert event["dst_port"] == 80
    detail = event["detail"]
    assert detail["auth"] == "basic"
    assert detail["credentials"] == "admin:S3cret-Pa55"
    assert detail["username"] == "admin"
    assert detail["method"] == "GET"
    assert detail["path"] == "/admin"
    assert detail["useragent"] == "python-requests/2.31"
    # El detalle completo cabe en el contrato v1 (límite del evento).
    assert len(json.dumps(event).encode()) < 8192


def test_http_get_without_basic_records_headers_but_no_credentials():
    raw = {
        "logtype": 3000,
        "logdata": {
            "SKIN": "nasLogin",
            "HOSTNAME": "10.66.0.3",
            "PATH": "/index.html",
            "METHOD": "GET",
            "USERAGENT": "curl/8.5.0",
            "REFERER": "http://ref.example/",
        },
        "src_host": "203.0.113.9",
        "src_port": 55000,
        "dst_host": "10.66.0.3",
        "dst_port": 80,
        "utc_time": "2026-11-17 10:00:01.000000",
    }
    event = normalize_raw("opencanary", "sw-access-01", raw)
    assert event["type"] == "http_request"
    assert "credentials" not in event["detail"]  # sin Basic no hay credenciales
    assert event["detail"]["referer"] == "http://ref.example/"
    assert event["detail"]["method"] == "GET"


def test_password_from_other_protocols_never_reaches_detail():
    """La excepción es solo para Basic de la trampa HTTP; el resto se redacta."""
    raw = {
        "logtype": 4002,
        "logdata": {"USERNAME": "root", "PASSWORD": "SENSITIVE-FIXTURE-PW"},
        "src_host": "198.51.100.7", "src_port": 55002, "dst_port": 22,
        "msg": "Login attempt [root/SENSITIVE-FIXTURE-PW] failed",
        "protocol": "ssh", "utc_time": "2026-11-17 10:00:02.000000",
    }
    event = normalize_raw("opencanary", "sw-access-01", raw)
    assert "SENSITIVE-FIXTURE-PW" not in json.dumps(event)
    assert "credentials" not in event.get("detail", {})
