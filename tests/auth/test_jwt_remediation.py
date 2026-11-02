"""Remediación JWT (PyJWT) — pruebas reales de la ruta de autenticación.

Cubre los 5 casos exigidos para cerrar los avisos de python-jose/Starlette:
login correcto, JWT mal firmado, token sin ``ver``, usuario cambiado/revocado
y API key (``np_...``) que no se confunde con un JWT. Sin sockets de host,
con credenciales sintéticas.
"""
import yaml
import pytest
from fastapi.testclient import TestClient

PASSWORD = "synthetic-password-0123456789"


@pytest.fixture
def jwt_env(tmp_path, monkeypatch):
    from app.core.security import hash_password
    from app.middleware import audit
    from app.routers import auth
    from app.core.limiter import limiter

    monkeypatch.setattr(limiter, "enabled", False)  # aislar del presupuesto global de login
    monkeypatch.setenv("NETPULSE_JWT_SECRET", "synthetic-jwt-remediation-secret-0123456789")
    monkeypatch.setattr(audit, "_log_async", lambda **kwargs: None)
    monkeypatch.setenv("DYSTOPIA_CONTROL_STATE", str(tmp_path))
    monkeypatch.setenv("DYSTOPIA_CONTROL_CONFIG", str(tmp_path / "config"))

    from app.services.security import api_keys_svc
    monkeypatch.setattr(api_keys_svc, "API_KEYS_FILE", tmp_path / "api_keys.json")

    users = tmp_path / "users.yaml"
    users.write_text(yaml.safe_dump({"users": [
        {"username": "viewer", "role": "viewer", "password_hash": hash_password(PASSWORD)},
    ]}))
    users.chmod(0o600)
    monkeypatch.setattr(auth, "USERS_FILE", users)

    from app.main import app
    with TestClient(app) as client:
        yield client, users


def _bearer(token):
    return {"Authorization": "Bearer " + token}


def test_login_correct_and_token_accepted(jwt_env):
    client, _ = jwt_env
    response = client.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD})
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert len(token.split(".")) == 3
    me = client.get("/api/auth/me", headers=_bearer(token))
    assert me.status_code == 200
    assert me.json() == {"username": "viewer", "role": "viewer"}


def test_mis_signed_jwt_rejected(jwt_env):
    client, _ = jwt_env
    first = client.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD})
    token = first.json()["access_token"]
    head, body, signature = token.split(".")
    # Testigo del test: el token intacto SÍ pasa, para que el fallo sea solo de firma.
    assert client.get("/api/auth/me", headers=_bearer(token)).status_code == 200

    # Falsificación: payload legítimo firmado con una clave distinta (PyJWT).
    from app.core import security
    import jwt as pyjwt
    payload = pyjwt.decode(token, security.JWT_SECRET, algorithms=[security.JWT_ALGORITHM], options={"verify_signature": False})
    forged = pyjwt.encode(payload, "wrong-synthetic-key-not-the-real-secret-1234", algorithm=security.JWT_ALGORITHM)
    assert forged.split(".")[2] != signature
    assert client.get("/api/auth/me", headers=_bearer(forged)).status_code == 401
    # Un byte alterado en la firma también debe fallar.
    tampered = f"{head}.{body}x{signature[:-1]}"
    assert client.get("/api/auth/me", headers=_bearer(tampered)).status_code == 401


def test_token_without_ver_claim_rejected(jwt_env):
    client, _ = jwt_env
    from app.core.security import create_access_token
    stale = create_access_token({"sub": "viewer", "role": "viewer"})  # sin "ver"
    assert client.get("/api/auth/me", headers=_bearer(stale)).status_code == 401


def test_changed_user_revokes_previous_token(jwt_env):
    client, users = jwt_env
    first = client.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD})
    old = _bearer(first.json()["access_token"])
    assert client.get("/api/auth/me", headers=old).status_code == 200

    # Rotación: cambia el hash ⇒ cambia el claim ver del hash ⇒ token anterior inválido.
    from app.core.security import hash_password
    users.write_text(yaml.safe_dump({"users": [
        {"username": "viewer", "role": "viewer", "password_hash": hash_password("rotated-password-0123456789")},
    ]}))
    users.chmod(0o600)
    assert client.get("/api/auth/me", headers=old).status_code == 401
    assert client.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD}).status_code == 401


def test_revoked_user_token_rejected(jwt_env):
    client, users = jwt_env
    first = client.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD})
    old = _bearer(first.json()["access_token"])
    users.write_text(yaml.safe_dump({"users": []}))
    users.chmod(0o600)
    assert client.get("/api/auth/me", headers=old).status_code == 401


def test_api_key_and_jwt_paths_do_not_cross(jwt_env, monkeypatch):
    # Nota: el fixture y el test comparten la misma instancia de monkeypatch;
    # nunca se llama a undo(): se restauran los originales con setattr explícito.
    import app.middleware.auth as auth_mw
    client, _ = jwt_env
    from app.services.security import api_keys_svc

    issued = api_keys_svc.create_api_key("remediation-check", role="viewer")
    key = issued["key"]
    assert key.startswith("np_")

    # Una API key no debe pasar nunca por la verificación de JWT: el test falla
    # si la ruta de JWT intenta decodificarla.
    real_verify_token = auth_mw.verify_token
    monkeypatch.setattr(auth_mw, "verify_token",
                        lambda _token: pytest.fail("API key went through JWT verification"))

    me = client.get("/api/auth/me", headers=_bearer(key))
    assert me.status_code == 200
    assert me.json()["username"] == f"apikey:{issued['name']}"

    # A la inversa: un JWT no debe evaluarse como API key.
    monkeypatch.setattr(auth_mw, "verify_token", real_verify_token)
    real_validate = api_keys_svc.validate_api_key
    monkeypatch.setattr(api_keys_svc, "validate_api_key",
                        lambda _key: pytest.fail("JWT went through API key validation"))
    valid = client.post("/api/auth/login", json={"username": "viewer", "password": PASSWORD})
    assert valid.status_code == 200, valid.text
    assert client.get("/api/auth/me", headers=_bearer(valid.json()["access_token"])).status_code == 200

    # Una key revocada se rechaza en la ruta de API keys.
    monkeypatch.setattr(api_keys_svc, "validate_api_key", real_validate)
    api_keys_svc.revoke_api_key(issued["id"])
    assert client.get("/api/auth/me", headers=_bearer(key)).status_code == 401
