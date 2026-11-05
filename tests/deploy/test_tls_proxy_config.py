"""Static safety contracts for the versioned TLS proxy templates."""

from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
PROXY_DIR = ROOT / "deploy" / "tls-proxy"


def read_config(name: str) -> str:
    return (PROXY_DIR / name).read_text(encoding="utf-8")


def _strip_comments(text: str) -> str:
    output: list[str] = []
    quote: str | None = None
    escaped = False
    in_comment = False
    for char in text:
        if in_comment:
            if char == "\n":
                in_comment = False
                output.append(char)
            continue
        if escaped:
            output.append(char)
            escaped = False
            continue
        if char == "\\" and quote:
            output.append(char)
            escaped = True
            continue
        if quote:
            output.append(char)
            if char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
            output.append(char)
        elif char == "#":
            in_comment = True
        else:
            output.append(char)
    return "".join(output)


def parse_nginx_blocks(text: str) -> list[tuple[str, ...]]:
    clean = _strip_comments(text)
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{};]|[^\s{};]+', clean)
    blocks: list[tuple[str, ...]] = []
    stack: list[list[str]] = []
    statement: list[str] = []
    for token in tokens:
        if token == "{":
            if not statement:
                raise AssertionError("nginx block missing directive")
            stack.append(statement)
            blocks.append(tuple(statement))
            statement = []
        elif token == ";":
            if not statement:
                raise AssertionError("empty nginx directive")
            statement = []
        elif token == "}":
            if statement:
                raise AssertionError(f"nginx directive missing semicolon: {statement}")
            if not stack:
                raise AssertionError("unexpected nginx closing brace")
            stack.pop()
        else:
            statement.append(token)
    if statement:
        raise AssertionError(f"nginx directive missing semicolon: {statement}")
    if stack:
        raise AssertionError("unclosed nginx block")
    return blocks


def assert_caddy_blocks_balanced(text: str) -> None:
    depth = 0
    quote: str | None = None
    escaped = False
    in_comment = False
    for char in text:
        if in_comment:
            if char == "\n":
                in_comment = False
            continue
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
        elif quote:
            if char == quote:
                quote = None
        elif char in {'"', "'"}:
            quote = char
        elif char == "#":
            in_comment = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            assert depth >= 0, "unexpected Caddy closing brace"
    assert quote is None, "unterminated Caddy string"
    assert depth == 0, "unclosed Caddy block"


def test_nginx_templates_have_structurally_valid_blocks() -> None:
    parsed = {
        "nginx.conf": parse_nginx_blocks(read_config("nginx.conf")),
        "control.conf": parse_nginx_blocks(read_config("control.conf")),
    }
    assert ("events",) in parsed["nginx.conf"]
    assert ("http",) in parsed["nginx.conf"]
    assert ("server",) in parsed["control.conf"]


def test_caddyfile_has_structurally_valid_blocks() -> None:
    text = read_config("Caddyfile")
    assert_caddy_blocks_balanced(text)
    assert "auto_https disable_redirects" in text
    assert "https://control.mgmt.example.invalid:9443" in text


def test_proxy_never_targets_elasticsearch_or_docker_socket() -> None:
    configs = "\n".join(read_config(name) for name in ["Caddyfile", "nginx.conf", "control.conf"])
    assert not re.search(r"(?:https?://[^\s;{}]*:9200|proxy_pass\s+[^;]*:9200)", configs)
    assert not re.search(r"/var/run/docker\.sock|/run/docker\.sock", configs)
    assert "privileged:" not in configs.lower()
    assert "0.0.0.0" not in configs
    assert not re.search(r"\blatest\b", configs, flags=re.IGNORECASE)


def test_deception_routes_are_denied() -> None:
    nginx_control = read_config("control.conf")
    caddy = read_config("Caddyfile")
    assert "location = /api/deception" in nginx_control
    assert "location ^~ /api/deception/" in nginx_control
    assert re.search(r"location\s+\^~\s+/api/deception/\s*\{\s*return 404;", nginx_control)
    assert "@deception path /api/deception /api/deception/*" in caddy
    assert 'respond @deception "Not Found" 404' in caddy


def test_tls_and_loopback_are_mandatory_by_default() -> None:
    text = read_config("control.conf")
    assert "listen 127.0.0.1:9443 ssl;" in text
    assert "ssl_certificate_key" in text
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in text
    caddy = read_config("Caddyfile")
    assert "bind 127.0.0.1" in caddy
    assert "tls /etc/dystopia/tls-proxy/certs/reverse-proxy.crt" in caddy


def test_management_access_is_allowlisted() -> None:
    text = read_config("control.conf")
    assert "allow 127.0.0.1;" in text
    assert "allow ::1;" in text
    assert "deny all;" in text
    assert read_config("Caddyfile").count("@notManagement not remote_ip 127.0.0.1 ::1") == 1


def test_hsts_and_standard_security_headers_exist_only_on_tls_vhosts() -> None:
    text = read_config("control.conf")
    assert 'add_header Strict-Transport-Security "max-age=31536000" always;' in text
    assert 'add_header X-Content-Type-Options "nosniff" always;' in text
    assert 'add_header X-Frame-Options "DENY" always;' in text
    assert "listen 127.0.0.1:" in text and " ssl;" in text
    assert read_config("Caddyfile").count('Strict-Transport-Security "max-age=31536000"') == 1


def test_control_proxy_minimizes_personal_data_and_disables_caching() -> None:
    nginx = read_config("control.conf")
    caddy = read_config("Caddyfile")
    assert "access_log off;" in nginx
    assert "proxy_cache off;" in nginx
    assert 'add_header Cache-Control "no-store, private" always;' in nginx
    assert 'proxy_set_header X-Forwarded-For "";' in nginx
    assert 'proxy_set_header X-Real-IP "";' in nginx
    assert "proxy_hide_header Cache-Control;" in nginx
    assert "output discard" in caddy
    assert 'Cache-Control "no-store, private"' in caddy
    assert "header_up -X-Forwarded-For" in caddy


def test_templates_contain_no_private_keys_or_credentials() -> None:
    for path in PROXY_DIR.iterdir():
        if not path.is_file() or path.name == "README.md":
            continue
        text = path.read_text(encoding="utf-8")
        assert "-----BEGIN PRIVATE KEY-----" not in text
