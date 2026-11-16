"""NetPulse — Fabric: credenciales cifradas en reposo (Fase 8).

Las credenciales señuelo del manifiesto **no** viajan al contenedor: el
agente no las necesita (los listeners usan personas) y ``device.json`` se
escribe sin ellas. Se guardan cifradas aparte con Fernet, para que un
futuro binding de honeypots reales pueda consumirlas sin exponerlas.

Clave (fail-closed, nunca en git):

- ``DYSTOPIA_FABRIC_KEY``: clave Fernet base64 (32 bytes) en el entorno, o
- ``/etc/dystopia/fabric.key`` (0600, la genera el instalador).

Sin clave válida cualquier operación lanza ``CredentialStoreError``; no
hay degradación a texto plano.

Formato del fichero ``<credentials_dir>/<device_id>.enc`` (0600, atómico)::

    <token Fernet en ASCII>\\n

y el texto cifrado es el sobre JSON
``{"v": 1, "device_id": "...", "credentials": [{...}]}``. El ``device_id``
del sobre se verifica al cargar para detectar ficheros intercambiados.
"""

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Optional

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

KEY_ENV = "DYSTOPIA_FABRIC_KEY"
KEY_FILE_ENV = "DYSTOPIA_FABRIC_KEY_FILE"
CREDENTIALS_DIR_ENV = "DYSTOPIA_FABRIC_CREDENTIALS_DIR"

KEY_FILE = Path(os.getenv(KEY_FILE_ENV, "/etc/dystopia/fabric.key"))
CREDENTIALS_DIR = Path(
    os.getenv(CREDENTIALS_DIR_ENV, "/var/lib/dystopia/fabric/credentials")
)
_DEVICE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_CREDENTIAL_FIELDS = ("username", "password", "service", "purpose")


class CredentialStoreError(RuntimeError):
    """Clave ausente/incorrecta o fichero de credenciales inválido."""


def _load_key() -> bytes:
    """Clave Fernet del entorno o del fichero 0600; falla cerrado."""
    raw = os.getenv(KEY_ENV, "").strip()
    if raw:
        key = raw.encode("ascii", errors="ignore")
    else:
        try:
            key = KEY_FILE.read_bytes().strip()
        except OSError as exc:
            raise CredentialStoreError(
                f"No hay clave del fabric: define {KEY_ENV} o instala "
                f"'{KEY_FILE}' (0600) con deploy/server/install-fabric-service.sh"
            ) from exc
    if not key:
        raise CredentialStoreError("La clave del fabric está vacía")
    try:
        Fernet(key)
    except (ValueError, TypeError) as exc:
        raise CredentialStoreError(
            "Clave Fernet inválida (debe ser base64 urlsafe de 32 bytes)"
        ) from exc
    return key


def _fernet() -> Fernet:
    return Fernet(_load_key())


def is_configured() -> bool:
    """True si hay una clave válida (no lanza)."""
    try:
        _load_key()
        return True
    except CredentialStoreError:
        return False


def _safe_device_id(device_id: str) -> str:
    if not isinstance(device_id, str) or not _DEVICE_ID_RE.fullmatch(device_id):
        raise CredentialStoreError(f"device_id no válido para el store: {device_id!r}")
    return device_id


def _clean_credentials(credentials: list[dict]) -> list[dict]:
    """Solo los campos del modelo, todos como texto."""
    cleaned: list[dict] = []
    for credential in credentials or []:
        if not isinstance(credential, dict):
            raise CredentialStoreError("Cada credencial debe ser un objeto")
        cleaned.append({
            field: str(credential.get(field) or "")
            for field in _CREDENTIAL_FIELDS
        })
    return cleaned


def encrypt_credentials(device_id: str, credentials: list[dict]) -> str:
    """Cifra la lista de credenciales de un dispositivo (sobre con device_id)."""
    envelope = {
        "v": 1,
        "device_id": _safe_device_id(device_id),
        "credentials": _clean_credentials(credentials),
    }
    payload = json.dumps(envelope, ensure_ascii=False, sort_keys=True)
    return _fernet().encrypt(payload.encode("utf-8")).decode("ascii")


def decrypt_credentials(token: str) -> list[dict]:
    """Descifra un token de credenciales; clave incorrecta → error."""
    if not token:
        raise CredentialStoreError("Token de credenciales vacío")
    try:
        raw = _fernet().decrypt(token.encode("ascii"))
    except InvalidToken as exc:
        raise CredentialStoreError(
            "Token de credenciales inválido o clave incorrecta"
        ) from exc
    try:
        envelope = json.loads(raw)
    except ValueError as exc:
        raise CredentialStoreError("Sobre de credenciales corrupto") from exc
    credentials = envelope.get("credentials") if isinstance(envelope, dict) else None
    if not isinstance(credentials, list):
        raise CredentialStoreError("Sobre de credenciales sin lista")
    return credentials


def _path_for(device_id: str) -> Path:
    return CREDENTIALS_DIR / f"{_safe_device_id(device_id)}.enc"


def store_for_device(device_id: str, credentials: list[dict]) -> Path:
    """Escribe ``<device_id>.enc`` (0600) de forma atómica."""
    path = _path_for(device_id)
    token = encrypt_credentials(device_id, credentials)
    try:
        CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(CREDENTIALS_DIR, 0o700)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(CREDENTIALS_DIR), prefix=".tmp-", suffix=".enc"
        )
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(token + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, path)
        except Exception:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise CredentialStoreError(
            f"No se pudo escribir '{path}': {exc}"
        ) from exc
    logger.info("[fabric] credenciales cifradas para '%s' → %s", device_id, path)
    return path


def load_for_device(device_id: str) -> list[dict]:
    """Carga y descifra las credenciales de un dispositivo ([] si no hay)."""
    path = _path_for(device_id)
    try:
        token = path.read_text(encoding="ascii").strip()
    except FileNotFoundError:
        return []
    except OSError as exc:
        raise CredentialStoreError(f"No se pudo leer '{path}': {exc}") from exc
    credentials = decrypt_credentials(token)
    # Verifica que el sobre pertenece al dispositivo (fichero intercambiado).
    try:
        raw = _fernet().decrypt(token.encode("ascii"))
        envelope = json.loads(raw)
    except (InvalidToken, ValueError) as exc:  # pragma: no cover - ya validado
        raise CredentialStoreError("Sobre de credenciales corrupto") from exc
    if envelope.get("device_id") != device_id:
        raise CredentialStoreError(
            f"El fichero de credenciales de '{device_id}' pertenece a "
            f"'{envelope.get('device_id')}'"
        )
    return credentials


def delete_for_device(device_id: str) -> bool:
    """Elimina el fichero cifrado del dispositivo (idempotente)."""
    path = _path_for(device_id)
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CredentialStoreError(f"No se pudo borrar '{path}': {exc}") from exc


def credentials_for(device_id: str, credentials: Optional[list[Any]]) -> list[dict]:
    """Normaliza credenciales del modelo (FabricCredential) para el store."""
    out: list[dict] = []
    for credential in credentials or []:
        if isinstance(credential, dict):
            out.append(credential)
        else:
            out.append({
                "username": getattr(credential, "username", ""),
                "password": getattr(credential, "password", ""),
                "service": getattr(credential, "service", ""),
                "purpose": getattr(credential, "purpose", ""),
            })
    return out
