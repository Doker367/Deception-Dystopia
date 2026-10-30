"""Fail-closed gate for the opt-in, disposable-lab end-to-end scenario.

Nothing here opens a connection on import. The gate is the only way the lab
test obtains a client, and it refuses to build one unless ALL of the following
are explicit and valid:

* ``DYSTOPIA_LAB_E2E=preflight|full`` selects the mode.
* ``DYSTOPIA_LAB_CONFIRM=DISPOSABLE-LAB-ONLY`` is the operator acknowledgement.
* ``DYSTOPIA_LAB_MARKER`` points to an operator-created marker file containing
  ``purpose=dystopia-disposable-lab`` and an ``authorization_id``.
* ``DYSTOPIA_LAB_TARGETS`` explicitly lists every host the scenario may touch.
* ``DYSTOPIA_LAB_SCENARIO`` points to a scenario whose addresses are RFC1918 /
  loopback / ULA (or explicit ``.lab``/``.lab.local``/``.test`` names) and are
  all present in the target allowlist. Public, documentation, metadata and
  carrier-grade addresses are refused; plain HTTP is refused outside loopback;
  URLs with embedded credentials are refused; credentials must live in
  owner-only token files, never in the scenario or the environment.

The test never sends exploits, never guesses passwords and never opens SSH:
the synthetic SSH step is performed by the operator and confirmed through
``DYSTOPIA_LAB_SSH_PERFORMED``.
"""
from __future__ import annotations

from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import ssl
import stat
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
import urllib.request
from urllib.request import ProxyHandler

CONFIRM_VALUE = "DISPOSABLE-LAB-ONLY"
PURPOSE = "dystopia-disposable-lab"
MODES = {"preflight", "full"}
LAB_NETWORKS = tuple(
    ip_network(net)
    for net in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "::1/128",
        "fc00::/7",
    )
)
LAB_NAME_SUFFIXES = (".lab", ".lab.local", ".test")
MAX_MARKER_BYTES = 4096
MAX_TOKEN_BYTES = 8192
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
INLINE_CREDENTIAL_KEYS = {
    "password", "passwd", "pwd", "passphrase", "secret", "client_secret",
    "token", "api_key", "apikey", "authorization", "private_key",
}
REQUIRED_SCENARIO_KEYS = ("lab", "dystopia", "elasticsearch", "kibana", "event", "poll")


class LabGateError(RuntimeError):
    pass


def is_lab_address(host):
    """True only for literal RFC1918/loopback/ULA addresses or *.lab names."""
    try:
        address = ip_address(host)
    except ValueError:
        name = host.rstrip(".").lower()
        return name == "localhost" or name.endswith(LAB_NAME_SUFFIXES)
    return any(address in network for network in LAB_NETWORKS)


def split_target(entry):
    entry = entry.strip()
    if not entry:
        raise LabGateError("empty entry in DYSTOPIA_LAB_TARGETS")
    if entry.startswith("["):
        end = entry.find("]")
        if end < 0:
            raise LabGateError("malformed IPv6 target in DYSTOPIA_LAB_TARGETS")
        host = entry[1:end]
        remainder = entry[end + 1:]
        if remainder and not re.fullmatch(r":\d{1,5}", remainder):
            raise LabGateError("malformed port in DYSTOPIA_LAB_TARGETS")
        return host
    if entry.count(":") == 1:
        host, port = entry.rsplit(":", 1)
        if port.isdigit():
            return host
    return entry


def parse_targets(value):
    if not value or not value.strip():
        raise LabGateError("DYSTOPIA_LAB_TARGETS is required (explicit host allowlist)")
    targets = set()
    for entry in value.split(","):
        host = split_target(entry)
        if not is_lab_address(host):
            raise LabGateError(f"target {host!r} is not a disposable-lab address")
        targets.add(host.lower())
    return targets


def _read_limited(path, limit):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise LabGateError(f"cannot open {path}: {exc.strerror}") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise LabGateError(f"{path} must be a regular file")
        if info.st_size > limit:
            raise LabGateError(f"{path} is larger than {limit} bytes")
        data = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(data) > limit:
        raise LabGateError(f"{path} is larger than {limit} bytes")
    return data


def read_marker(path):
    data = _read_limited(path, MAX_MARKER_BYTES).decode("utf-8", "strict")
    values = {}
    for line in data.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    if values.get("purpose") != PURPOSE:
        raise LabGateError(f"marker purpose must be {PURPOSE!r}")
    if not values.get("authorization_id"):
        raise LabGateError("marker requires a non-empty authorization_id")
    return values


def _validate_url(url, label):
    if not isinstance(url, str) or not url:
        raise LabGateError(f"{label}: base_url is required")
    parsed = urlsplit(url)
    if parsed.scheme not in {"https", "http"}:
        raise LabGateError(f"{label}: only http/https URLs are accepted")
    if parsed.username or parsed.password:
        raise LabGateError(f"{label}: credentials must not appear in URLs")
    if parsed.fragment:
        raise LabGateError(f"{label}: URL fragments are not accepted")
    try:
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise LabGateError(f"{label}: malformed URL") from None
    if not host:
        raise LabGateError(f"{label}: URL has no host")
    if not is_lab_address(host):
        raise LabGateError(f"{label}: {host!r} is not a disposable-lab address")
    if parsed.scheme == "http":
        if not _is_ip(host) or not ip_address(host).is_loopback:
            raise LabGateError(f"{label}: plain HTTP is only accepted on a loopback literal")
    if port is not None and not 1 <= port <= 65535:
        raise LabGateError(f"{label}: invalid port")
    return host.lower()


def _is_ip(host):
    try:
        ip_address(host)
        return True
    except ValueError:
        return False


def _validate_file(path, label, *, owner_only=False, max_bytes=MAX_TOKEN_BYTES):
    if not path:
        return None
    candidate = Path(path)
    if not candidate.is_file():
        raise LabGateError(f"{label}: {path} does not exist or is not a regular file")
    info = candidate.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise LabGateError(f"{label}: symlinks are not accepted")
    if info.st_size > max_bytes:
        raise LabGateError(f"{label}: file exceeds {max_bytes} bytes")
    if owner_only and info.st_mode & 0o077:
        raise LabGateError(f"{label}: permissions must be owner-only (expected 0600/0400)")
    return str(candidate)


def _reject_inline_credentials(value, path="$"):
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).lower() in INLINE_CREDENTIAL_KEYS:
                raise LabGateError(
                    f"{path}.{key}: inline credentials are forbidden; use a token_file"
                )
            _reject_inline_credentials(nested, f"{path}.{key}")
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            _reject_inline_credentials(nested, f"{path}[{index}]")


class LabGate:
    def __init__(self, scenario_path, env):
        self.env = dict(env)
        self.mode = self._mode()
        self.scenario_path = scenario_path
        self.scenario = self._load_scenario(scenario_path)
        self.marker = self._marker()
        self.targets = parse_targets(env.get("DYSTOPIA_LAB_TARGETS", ""))
        self._validate_scenario()
        self._tokens = {}

    # -- construction ----------------------------------------------------- #
    @classmethod
    def from_environ(cls, env):
        mode = env.get("DYSTOPIA_LAB_E2E")
        if not mode:
            return None
        if env.get("DYSTOPIA_LAB_CONFIRM") != CONFIRM_VALUE:
            raise LabGateError(
                f"DYSTOPIA_LAB_CONFIRM must be exactly {CONFIRM_VALUE}"
            )
        scenario_path = env.get("DYSTOPIA_LAB_SCENARIO")
        if not scenario_path:
            raise LabGateError("DYSTOPIA_LAB_SCENARIO is required in lab mode")
        marker_path = env.get("DYSTOPIA_LAB_MARKER")
        if not marker_path:
            raise LabGateError("DYSTOPIA_LAB_MARKER is required in lab mode")
        return cls(scenario_path, env)

    def _mode(self):
        mode = self.env.get("DYSTOPIA_LAB_E2E", "")
        if mode == "1":
            mode = "preflight"
        if mode not in MODES:
            raise LabGateError("DYSTOPIA_LAB_E2E must be 'preflight' or 'full'")
        return mode

    def _load_scenario(self, path):
        data = _read_limited(path, 256 * 1024)
        try:
            scenario = json.loads(data)
        except (ValueError, UnicodeDecodeError):
            raise LabGateError("lab scenario is not valid UTF-8 JSON") from None
        if not isinstance(scenario, dict):
            raise LabGateError("lab scenario must be a JSON object")
        missing = [key for key in REQUIRED_SCENARIO_KEYS if key not in scenario]
        if missing:
            raise LabGateError(f"lab scenario is missing {', '.join(missing)}")
        _reject_inline_credentials(scenario)
        return scenario

    # -- validation ------------------------------------------------------- #
    def _marker(self):
        if not self.env.get("DYSTOPIA_LAB_MARKER"):
            raise LabGateError("DYSTOPIA_LAB_MARKER is required in lab mode")
        values = read_marker(self.env["DYSTOPIA_LAB_MARKER"])
        lab = self.scenario.get("lab") or {}
        if lab.get("purpose") != PURPOSE:
            raise LabGateError(f"scenario lab.purpose must be {PURPOSE!r}")
        if lab.get("authorization_id") != values["authorization_id"]:
            raise LabGateError("scenario authorization_id does not match the marker")
        return values

    def _validate_scenario(self):
        scenario = self.scenario
        for section in ("dystopia", "elasticsearch", "kibana"):
            block = scenario.get(section)
            if not isinstance(block, dict):
                raise LabGateError(f"scenario.{section} must be an object")
            host = _validate_url(block.get("base_url"), f"scenario.{section}.base_url")
            if host not in self.targets:
                raise LabGateError(
                    f"scenario.{section} host {host!r} is not in DYSTOPIA_LAB_TARGETS"
                )
            token_file = block.get("token_file")
            if token_file:
                _validate_file(
                    token_file,
                    f"scenario.{section}.token_file",
                    owner_only=True,
                )
            ca_file = block.get("ca_file")
            if ca_file:
                _validate_file(
                    ca_file,
                    f"scenario.{section}.ca_file",
                    owner_only=False,
                    max_bytes=1024 * 1024,
                )
        ssh = scenario.get("ssh") or {}
        ssh_host = ssh.get("host")
        if ssh_host and ssh_host.lower() not in self.targets:
            raise LabGateError("scenario.ssh.host is not in DYSTOPIA_LAB_TARGETS")
        event = scenario.get("event") or {}
        for field in ("device_id", "segment_id", "persona", "instance_id"):
            if not isinstance(event.get(field), str) or not event[field]:
                raise LabGateError(f"scenario.event.{field} is required")

    # -- credentials ------------------------------------------------------ #
    def token(self, service):
        if service in self._tokens:
            return self._tokens[service]
        path = (self.scenario.get(service) or {}).get("token_file")
        if not path:
            return None
        raw = _read_limited(path, MAX_TOKEN_BYTES)
        _validate_file(path, f"scenario.{service}.token_file", owner_only=True)
        value = raw.decode("utf-8", "strict").strip()
        if not value or "\n" in value:
            raise LabGateError(f"{service} token file must contain a single non-empty line")
        header = value if re.match(r"(?i)^(bearer|apikey|basic)\s+\S+", value) else f"Bearer {value}"
        self._tokens[service] = header
        return header

    def client(self, service):
        block = self.scenario[service]
        return LabClient(
            service,
            block["base_url"],
            token=self.token(service),
            ca_file=block.get("ca_file"),
        )

    def summary(self):
        return {
            "mode": self.mode,
            "authorization_id": self.marker["authorization_id"],
            "targets": sorted(self.targets),
            "device_id": self.scenario["event"]["device_id"],
            "index_pattern": self.scenario["elasticsearch"].get("index_pattern", "logstash-*"),
        }


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise LabGateError("HTTP redirects are refused in the lab harness")


class LabClient:
    """Small JSON client that never logs headers, bodies or token values."""

    def __init__(self, name, base_url, token=None, ca_file=None, timeout=10):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        handlers = [_NoRedirect(), ProxyHandler({})]
        if ca_file:
            context = ssl.create_default_context(cafile=ca_file)
            handlers.append(urllib.request.HTTPSHandler(context=context))
        self._opener = urllib.request.build_opener(*handlers)

    def request(self, method, path, body=None, params=None):
        if not isinstance(path, str) or not path.startswith("/"):
            raise LabGateError("client paths must be absolute and stay on the lab base URL")
        if "://" in path:
            raise LabGateError("client paths must not be absolute URLs")
        url = self.base_url + path
        if params:
            query = urlencode([(str(k), str(v)) for k, v in params.items()])
            url = url + ("&" if "?" in url else "?") + query
        parsed = urlsplit(url)
        if parsed.hostname is None or not is_lab_address(parsed.hostname):
            raise LabGateError("refusing request to a non-lab destination")
        data = None
        headers = {"Accept": "application/json"}
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode()
            headers["Content-Type"] = "application/json"
        if self._token:
            headers["Authorization"] = self._token
        request = urllib.request.Request(url, data=data, headers=headers, method=method.upper())
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                status = response.status
        except HTTPError as exc:
            raise LabGateError(
                f"{self.name} {method.upper()} {path}: HTTP {exc.code}"
            ) from None
        except (URLError, OSError) as exc:
            reason = getattr(exc, "reason", None) or exc.__class__.__name__
            raise LabGateError(f"{self.name} {method.upper()} {path}: {reason}") from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise LabGateError(f"{self.name} {method.upper()} {path}: response too large")
        if not raw:
            return status, None
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, raw.decode("utf-8", "replace")[:512]


def resolve_pointer(document, pointer):
    """Resolve ``a.b[0].c`` in a JSON document."""
    if not pointer:
        return document
    current = document
    for chunk in pointer.split("."):
        match = re.fullmatch(r"([^\[\]]+)((?:\[\d+\])*)", chunk)
        if not match:
            raise LabGateError(f"invalid scenario pointer {pointer!r}")
        key, indexes = match.groups()
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
        for index in re.findall(r"\[(\d+)\]", indexes):
            if not isinstance(current, list) or int(index) >= len(current):
                return None
            current = current[int(index)]
    return current


def evaluate_check(document, check):
    actual = resolve_pointer(document, check.get("pointer", ""))
    op = check.get("op", "equals")
    expected = check.get("value")
    if op == "equals":
        return actual == expected
    if op == "in":
        return actual in (expected or [])
    if op == "exists":
        return actual is not None
    if op == "gte":
        return actual is not None and actual >= expected
    if op == "contains_value":
        if isinstance(actual, list):
            for item in actual:
                if item == expected:
                    return True
                if isinstance(item, dict) and expected in item.values():
                    return True
            return False
        if isinstance(actual, dict):
            return expected in actual.values()
        return actual == expected
    raise LabGateError(f"unsupported scenario check op {op!r}")


def es_term_query(field, value, extra_filters=()):
    filters = [{"term": {field: value}}, *extra_filters]
    return {"bool": {"filter": filters}}


def kibana_filter_to_es(filter_spec):
    field = filter_spec["field"]
    op = filter_spec.get("op", "eq")
    value = filter_spec.get("value")
    if op == "eq":
        return {"term": {field: value}}
    if op == "gte_lte":
        return {"range": {field: {"gte": value, "lte": filter_spec.get("upper")}}}
    if op in {"gte", "lte"}:
        return {"range": {field: {op: value}}}
    raise LabGateError(f"unsupported lab filter op {op!r}")


def quote_index(pattern):
    return quote(pattern, safe="*,-_.")
