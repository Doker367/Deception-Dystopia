"""NetPulse — Fabric: engine remoto (Fase 4d).

Implementa el Protocol ``FabricEngine`` hablando con el **servicio del
host** (``app/services/fabric/host_service.py``) por HTTP con token
bearer. El control corre endurecido sin OVS/Docker; el fabric real se
ejecuta en el host y este engine es su cliente.

Verificación de manifiesto (decisión documentada)
------------------------------------------------
Antes de ``deploy`` **y** de ``destroy`` se hace ``GET /status`` y se
compara ``manifest_hash`` (SHA-256 de los **bytes** del manifiesto, igual
que calcula el servicio del host) con el hash del manifiesto local. Si
difieren se aborta con error accionable: así nunca se despliega (ni se
destruye) una topología distinta de la que muestra la UI. Requiere que el
control tenga el mismo archivo montado (ver ``deploy/local/docker-compose.yml``).

Errores
-------
Todo fallo se mapea a ``FabricDeployError`` con detalle accionable:
401 (token), 409 (ocupado), 422/503 (manifiesto del host), 502 (engine),
500 (fallo interno), timeout/red. **Sin reintentos automáticos**: son
operaciones mutantes; el reintento lo decide el operador/controller.

El último resultado se guarda en ``last_result``/``last_destroy_result``
con la misma forma que ``OvsFabricEngine`` (``DeployResult``/
``DestroyResult``), así que controller/API no cambian.
"""

import hashlib
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from app.services.fabric.controller import FabricPlan
from app.services.fabric.deploy import DeployResult, DestroyResult, FabricDeployError
from app.services.fabric.models import FabricTopology

logger = logging.getLogger(__name__)

REMOTE_URL_ENV = "DYSTOPIA_FABRIC_REMOTE_URL"
REMOTE_TOKEN_ENV = "DYSTOPIA_FABRIC_REMOTE_TOKEN"
REMOTE_TIMEOUT_ENV = "DYSTOPIA_FABRIC_REMOTE_TIMEOUT"
# Misma variable que usa el servicio del host: en el control apunta a la
# copia montada del manifiesto para verificar el hash.
REMOTE_MANIFEST_ENV = "DYSTOPIA_FABRIC_MANIFEST"
DEFAULT_REMOTE_TIMEOUT = 120.0
MIN_TOKEN_LENGTH = 32


class RemoteEngineConfigError(RuntimeError):
    """Configuración del engine remoto inválida (URL/token/timeout)."""


@dataclass(frozen=True)
class RemoteEngineSettings:
    """Configuración inmutable del engine remoto."""

    base_url: str
    token: str
    timeout: float
    manifest: Path


def load_remote_settings() -> RemoteEngineSettings:
    """Lee la configuración del entorno; falla accionable si falta algo."""
    base_url = os.getenv(REMOTE_URL_ENV, "").strip().rstrip("/")
    if not base_url:
        raise RemoteEngineConfigError(
            f"{REMOTE_URL_ENV} es obligatorio para el engine 'remote' "
            "(p. ej. http://host.docker.internal:8090)"
        )
    token = os.getenv(REMOTE_TOKEN_ENV, "")
    if len(token) < MIN_TOKEN_LENGTH:
        raise RemoteEngineConfigError(
            f"{REMOTE_TOKEN_ENV} debe existir y tener al menos "
            f"{MIN_TOKEN_LENGTH} caracteres (el mismo token del servicio del host)"
        )
    raw_timeout = os.getenv(REMOTE_TIMEOUT_ENV, str(DEFAULT_REMOTE_TIMEOUT)).strip()
    try:
        timeout = float(raw_timeout)
    except ValueError as exc:
        raise RemoteEngineConfigError(
            f"{REMOTE_TIMEOUT_ENV} debe ser un número de segundos (recibido {raw_timeout!r})"
        ) from exc
    if timeout <= 0:
        raise RemoteEngineConfigError(f"{REMOTE_TIMEOUT_ENV} debe ser > 0")
    manifest = Path(os.getenv(REMOTE_MANIFEST_ENV, "config/deception/network.yaml"))
    return RemoteEngineSettings(
        base_url=base_url, token=token, timeout=timeout, manifest=manifest
    )


def _file_hash(path: Path) -> str:
    """SHA-256 de los bytes del manifiesto (mismo cálculo que el host)."""
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


class RemoteFabricEngine:
    """``FabricEngine`` que opera el fabric vía el servicio del host."""

    kind = "remote"  # selector de ``DYSTOPIA_FABRIC_ENGINE``

    def __init__(
        self,
        settings: Optional[RemoteEngineSettings] = None,
        client: Optional[httpx.Client] = None,
    ):
        self._settings = settings or load_remote_settings()
        self._client = client or httpx.Client(
            base_url=self._settings.base_url,
            timeout=self._settings.timeout,
            headers={"Authorization": f"Bearer {self._settings.token}"},
        )
        self.last_result: Optional[DeployResult] = None
        self.last_destroy_result: Optional[DestroyResult] = None

    # ── FabricEngine ────────────────────────────────────────

    def deploy(self, plan: FabricPlan, topology: FabricTopology) -> None:
        """Despliega en el host tras verificar que el manifiesto coincide."""
        self.last_result = None
        self._verify_manifest("deploy")
        payload = self._request("POST", "/deploy", "deploy")
        self.last_result = DeployResult.model_validate(payload)
        logger.info(
            "[fabric-remote] deploy remoto: %d bridges, %d enlaces, %d contenedores "
            "(%d fallidos)",
            len(self.last_result.bridges_created),
            len(self.last_result.links_created),
            len(self.last_result.containers_created),
            len(self.last_result.containers_failed),
        )

    def destroy(self, topology: FabricTopology) -> None:
        """Destruye en el host tras verificar que el manifiesto coincide."""
        self.last_destroy_result = None
        self._verify_manifest("destroy")
        payload = self._request("POST", "/destroy", "destroy")
        self.last_destroy_result = DestroyResult.model_validate(payload)
        logger.info(
            "[fabric-remote] destroy remoto: %d bridges, %d contenedores eliminados",
            len(self.last_destroy_result.bridges_removed),
            len(self.last_destroy_result.containers_removed),
        )

    def health(self) -> dict:
        """Estado real del fabric según el servicio del host (``GET /health``).

        Devuelve el payload del host en la misma forma que
        ``lifecycle.health``: ``runtime_available``, ``healthy``, ``checks``
        y el detalle de bridges/links/devices.
        """
        payload = self._request("GET", "/health", "health")
        return payload

    def status(self) -> dict:
        """Estado del servicio del host (``GET /status``), incluido el forwarder."""
        return self._request("GET", "/status", "status")

    # ── HTTP ────────────────────────────────────────────────

    def _verify_manifest(self, operation: str) -> None:
        """Compara el hash del manifiesto local con el del host (GET /status)."""
        local = _file_hash(self._settings.manifest)
        if not local:
            raise FabricDeployError([
                f"{operation}: no se puede leer el manifiesto local "
                f"'{self._settings.manifest}' para verificar el hash"
            ])
        status = self._request("GET", "/status", operation)
        remote = str(status.get("manifest_hash") or "")
        if remote != local:
            raise FabricDeployError([
                f"{operation}: el manifiesto del servicio del host difiere del local "
                f"(host={remote[:12] or 'vacío'}…, local={local[:12]}…); sincroniza "
                "config/deception/network.yaml antes de operar el fabric"
            ])

    def _request(self, method: str, path: str, operation: str) -> dict:
        """Petición HTTP sin reintentos; fallos → ``FabricDeployError``."""
        try:
            response = self._client.request(method, path)
        except httpx.TimeoutException as exc:
            raise FabricDeployError([
                f"{operation}: el servicio del host no respondió en "
                f"{self._settings.timeout:g}s ({type(exc).__name__}); "
                f"revisa {REMOTE_TIMEOUT_ENV}"
            ]) from exc
        except httpx.HTTPError as exc:
            raise FabricDeployError([
                f"{operation}: no se pudo contactar con el servicio del host "
                f"({self._settings.base_url}): {exc}"
            ]) from exc

        if response.status_code == 200:
            try:
                return response.json()
            except ValueError as exc:
                raise FabricDeployError([
                    f"{operation}: el host devolvió una respuesta no JSON"
                ]) from exc
        raise FabricDeployError(self._error_for(operation, response))

    @staticmethod
    def _detail(response: httpx.Response) -> dict:
        """Cuerpo JSON; desenvuelve el sobre ``detail`` de FastAPI."""
        try:
            data = response.json()
        except ValueError:
            return {}
        if isinstance(data, dict) and isinstance(data.get("detail"), dict):
            return data["detail"]
        return data if isinstance(data, dict) else {}

    def _error_for(self, operation: str, response: httpx.Response) -> list[str]:
        """Mensaje accionable por código de estado del servicio del host."""
        detail = self._detail(response)
        errors = [str(error) for error in detail.get("errors", [])]
        message = str(detail.get("message") or "")
        joined = "; ".join(errors) or message or "sin detalle"
        status = response.status_code
        if status == 401:
            return [f"{operation}: token inválido o ausente en el servicio del "
                    f"host; revisa {REMOTE_TOKEN_ENV}"]
        if status == 409:
            return [f"{operation}: el servicio del host está ocupado "
                    "(otra operación en curso); reintenta en unos segundos"]
        if status == 422:
            return [f"{operation}: el manifiesto del host es inválido: {joined}"]
        if status == 503:
            return [f"{operation}: el host no puede leer su manifiesto: {joined}"]
        if status == 502:
            return [f"{operation}: el engine del host falló: {joined}"]
        if status == 500:
            return [f"{operation}: fallo interno en el host: {joined}"]
        return [f"{operation}: el host respondió HTTP {status}: "
                f"{response.text[:200] or 'sin cuerpo'}"]
