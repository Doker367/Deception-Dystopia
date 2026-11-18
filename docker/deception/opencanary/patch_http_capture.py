#!/usr/bin/env python3
"""Build-time patch: capture attacker data from every OpenCanary HTTP request.

Only runs inside the pinned OpenCanary image, after ``patch_fp.py``. Deja el
módulo HTTP de OpenCanary registrando, vía ``factory.log``, los campos que el
panel necesita para la ficha del atacante:

* ``GET`` (logtype 3000): añade ``METHOD`` y ``REFERER`` al logdata nativo
  (PATH/USERAGENT/HOSTNAME/SKIN ya vienen de upstream); ``src_ip``/``src_port``
  los añade ``CanaryService.log`` desde el transport.
* ``POST`` de login (logtype 3001): ídem, conservando ``USERNAME``/``PASSWORD``
  nativos y anotando el esquema si trae ``Authorization``.
* ``Authorization: Basic ...`` en CUALQUIER ruta/método: las credenciales se
  descodifican y se registran (logtype 3001, ``AUTH: basic``) antes del
  enrutado —cubre también 404 y métodos no implementados— y la respuesta es
  ``401`` + ``WWW-Authenticate: Basic``, como un dispositivo real que exige
  credenciales. El normalizador lleva la pareja a ``detail.credentials``
  (mismo criterio que las credenciales capturadas del fabric, §12 fase 7).

Todos los valores capturados se acotan (128/256/512 bytes) y se copian tal
cual (cadena, sin ejecutar nada). No se lee el cuerpo de las peticiones.
"""

from pathlib import Path
import sys

HTTP = Path("/usr/local/lib/python3.12/site-packages/opencanary/modules/http.py")

HELPERS = '''

def _dystopia_capture(value, limit):
    """Copia acotada de entrada hostil (nunca se ejecuta)."""
    if value is None:
        return ""
    text = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    return text[:limit]


def _dystopia_basic_auth(header):
    """Descodifica credenciales RFC 7617 Basic. Nunca lanza."""
    from base64 import b64decode

    parts = header.split(None, 1)
    if len(parts) != 2:
        return "<not supplied>", ""
    try:
        text = b64decode(parts[1].strip(), validate=False).decode("utf-8", "replace")
    except Exception:
        return "<not supplied>", ""
    username, _, password = text.partition(":")
    return username[:128] or "<not supplied>", password[:256]


def _dystopia_log_basic(factory, request, auth):
    """Registra un intento con credenciales Basic y responde 401."""
    logdata = {
        "USERNAME": _dystopia_basic_auth(auth)[0],
        "PASSWORD": _dystopia_basic_auth(auth)[1],
        "AUTH": "basic",
        "SKIN": getattr(factory, "skin", ""),
        "HOSTNAME": request.getRequestHostname(),
        "PATH": request.path,
        "METHOD": _dystopia_capture(request.method, 16),
        "USERAGENT": _dystopia_capture(request.getHeader("user-agent"), 512)
        or "<not supplied>",
    }
    referer = _dystopia_capture(request.getHeader("referer"), 512)
    if referer:
        logdata["REFERER"] = referer
    factory.log(logdata, transport=request.transport,
                logtype=factory.logger.LOG_HTTP_POST_LOGIN_ATTEMPT)
    request.setResponseCode(401)
    request.setHeader(b"WWW-Authenticate", b'Basic realm="Restricted"')
    request.setHeader(b"Content-Type", b"text/html; charset=utf-8")
    body = (b"<html><head><title>401 Unauthorized</title></head>"
            b"<body><h1>401 Unauthorized</h1></body></html>")
    request.setHeader(b"Content-Length", str(len(body)).encode())
    request.write(body)
    request.finish()
'''

PROCESS_NEEDLE = '''    def process(self):
        if self.method.decode("utf-8") not in self.allowedMethods:
'''

PROCESS_PATCHED = '''    def process(self):
        # (dystopia) Basic auth en cualquier ruta/método: se registra antes
        # del enrutado (cubre también 404 y métodos no implementados).
        auth = self.getHeader("authorization")
        site = getattr(self.channel, "site", None)
        factory = getattr(site, "dystopia_factory", None)
        if auth is not None and factory is not None \\
                and auth.lower().startswith("basic "):
            _dystopia_log_basic(factory, self, auth)
            return
        if self.method.decode("utf-8") not in self.allowedMethods:
'''

SITE_NEEDLE = '''        site = CanaryHttpServiceSite(wrapped)
        return internet.TCPServer(self.port, site, interface=self.listen_addr)
'''

SITE_PATCHED = '''        site = CanaryHttpServiceSite(wrapped)
        # (dystopia) referencia al factory para la captura de Basic auth.
        site.dystopia_factory = self
        return internet.TCPServer(self.port, site, interface=self.listen_addr)
'''

GET_NEEDLE = '''            logdata = {
                "SKIN": self.skin,
                "HOSTNAME": request.getRequestHostname(),
                "PATH": request.path,
                "USERAGENT": useragent,
            }

            logtype = self.factory.logger.LOG_HTTP_GET
'''

GET_PATCHED = '''            logdata = {
                "SKIN": self.skin,
                "HOSTNAME": request.getRequestHostname(),
                "PATH": request.path,
                "METHOD": "GET",
                "USERAGENT": useragent,
            }
            _referer = _dystopia_capture(request.getHeader("referer"), 512)
            if _referer:
                logdata["REFERER"] = _referer

            logtype = self.factory.logger.LOG_HTTP_GET
'''

POST_NEEDLE = '''        logdata = {
            "USERNAME": username,
            "PASSWORD": password,
            "SKIN": self.skin,
            "HOSTNAME": request.getRequestHostname(),
            "PATH": request.path,
            "USERAGENT": useragent,
        }
'''

POST_PATCHED = '''        logdata = {
            "USERNAME": username,
            "PASSWORD": password,
            "SKIN": self.skin,
            "HOSTNAME": request.getRequestHostname(),
            "PATH": request.path,
            "METHOD": "POST",
            "USERAGENT": useragent,
        }
        _referer = _dystopia_capture(request.getHeader("referer"), 512)
        if _referer:
            logdata["REFERER"] = _referer
        _auth = _dystopia_capture(request.getHeader("authorization"), 32)
        if _auth:
            logdata["AUTH"] = _auth.split(None, 1)[0]
'''


def patch_http(path: Path = HTTP) -> None:
    """Aplica el parche sobre el módulo instalado; idempotente."""
    source = path.read_text(encoding="utf-8")
    if "_dystopia_log_basic" in source:
        return  # ya aplicado en esta imagen
    replacements = (
        ("class CanaryRequest(Request):", HELPERS + "\n\nclass CanaryRequest(Request):",
         "clase CanaryRequest"),
        (PROCESS_NEEDLE, PROCESS_PATCHED, "CanaryRequest.process"),
        (SITE_NEEDLE, SITE_PATCHED, "CanaryHTTP.getService"),
        (GET_NEEDLE, GET_PATCHED, "logdata de render_GET"),
        (POST_NEEDLE, POST_PATCHED, "logdata de render_POST"),
    )
    for needle, replacement, name in replacements:
        if needle not in source:
            raise SystemExit(f"{name} no encontrado en el módulo HTTP de OpenCanary")
        source = source.replace(needle, replacement, 1)
    compile(source, str(path), "exec")  # el parche nunca deja el módulo roto
    path.write_text(source, encoding="utf-8")


if __name__ == "__main__":
    # Ruta alternativa opcional (tests); dentro de la imagen usa la ruta fija.
    patch_http(Path(sys.argv[1]) if len(sys.argv) > 1 else HTTP)
