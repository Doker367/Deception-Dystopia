"""Pruebas del almacén de credenciales cifradas del fabric (Fase 8).

Fernet con clave temporal: roundtrip, fichero .enc sin texto plano,
clave incorrecta, fail-closed sin clave, escritura atómica y binding por
device_id.
"""

import os
import stat
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from app.services.fabric import credential_store  # noqa: E402

CREDS = [
    {"username": "admin", "password": "admin123", "service": "ssh",
     "purpose": "señuelo"},
    {"username": "root", "password": "toor", "service": "ssh", "purpose": ""},
]


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """Clave y directorio temporales (sin tocar /etc ni /var)."""
    key_file = tmp_path / "fabric.key"
    key_file.write_bytes(Fernet.generate_key() + b"\n")
    monkeypatch.setattr(credential_store, "KEY_FILE", key_file)
    monkeypatch.setattr(credential_store, "CREDENTIALS_DIR", tmp_path / "credentials")
    monkeypatch.delenv(credential_store.KEY_ENV, raising=False)
    return credential_store


def test_roundtrip_cifrado(store):
    token = store.encrypt_credentials("pc-01", CREDS)
    assert "admin123" not in token
    assert store.decrypt_credentials(token) == CREDS


def test_store_y_load_fichero_0600(store):
    path = store.store_for_device("pc-01", CREDS)
    assert path.name == "pc-01.enc"
    assert path.stat().st_mode & stat.S_IRWXU == stat.S_IRUSR | stat.S_IWUSR
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    text = path.read_text(encoding="ascii")
    assert "admin123" not in text
    assert "toor" not in text
    assert store.load_for_device("pc-01") == CREDS


def test_load_sin_fichero_devuelve_vacio(store):
    assert store.load_for_device("no-existe") == []


def test_clave_incorrecta_falla(store):
    token = store.encrypt_credentials("pc-01", CREDS)
    store.store_for_device("pc-02", CREDS)
    # Otra clave distinta en el fichero.
    store.KEY_FILE.write_bytes(Fernet.generate_key() + b"\n")
    with pytest.raises(store.CredentialStoreError):
        store.decrypt_credentials(token)
    with pytest.raises(store.CredentialStoreError):
        store.load_for_device("pc-02")


def test_sin_clave_falla_cerrado(store):
    store.KEY_FILE.unlink()
    with pytest.raises(store.CredentialStoreError) as excinfo:
        store.encrypt_credentials("pc-01", CREDS)
    assert "clave" in str(excinfo.value).lower()
    assert store.is_configured() is False


def test_clave_por_entorno(store, monkeypatch):
    store.KEY_FILE.unlink()
    monkeypatch.setenv(store.KEY_ENV, Fernet.generate_key().decode())
    assert store.is_configured() is True
    token = store.encrypt_credentials("pc-01", CREDS)
    assert store.decrypt_credentials(token) == CREDS


def test_clave_invalida_falla(store):
    store.KEY_FILE.write_text("no-es-una-clave-fernet", encoding="ascii")
    with pytest.raises(store.CredentialStoreError):
        store.encrypt_credentials("pc-01", CREDS)


def test_escritura_atomica(store, monkeypatch):
    store.store_for_device("pc-01", CREDS)
    original = store.load_for_device("pc-01")

    def failing_replace(*args, **kwargs):
        raise OSError("disco lleno")

    original_replace = os.replace
    monkeypatch.setattr(os, "replace", failing_replace)
    with pytest.raises(store.CredentialStoreError):
        store.store_for_device("pc-01", [{"username": "x", "password": "y"}])
    monkeypatch.setattr(os, "replace", original_replace)
    # El fichero anterior sigue intacto y no quedan temporales.
    assert store.load_for_device("pc-01") == original
    assert list(store.CREDENTIALS_DIR.glob(".tmp-*")) == []


def test_device_id_invalido(store):
    with pytest.raises(store.CredentialStoreError):
        store.store_for_device("../evil", CREDS)
    with pytest.raises(store.CredentialStoreError):
        store.encrypt_credentials("con/barra", CREDS)


def test_fichero_intercambiado_falla(store):
    path = store.store_for_device("pc-01", CREDS)
    path.rename(store.CREDENTIALS_DIR / "srv-01.enc")
    with pytest.raises(store.CredentialStoreError) as excinfo:
        store.load_for_device("srv-01")
    assert "pertenece" in str(excinfo.value)


def test_delete_idempotente(store):
    store.store_for_device("pc-01", CREDS)
    assert store.delete_for_device("pc-01") is True
    assert store.delete_for_device("pc-01") is False
    assert store.load_for_device("pc-01") == []


def test_credentials_for_modelos(store):
    from app.services.fabric.models import FabricCredential

    normalized = store.credentials_for("pc-01", [
        FabricCredential(username="admin", password="admin123", service="ssh"),
    ])
    assert normalized == [{
        "username": "admin", "password": "admin123",
        "service": "ssh", "purpose": "",
    }]
