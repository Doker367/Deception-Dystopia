"""Local administrative prototype. No workload activation or containment attestation.

The only process operation is a fixed nft invocation with internally rendered
stdin. No shell, arbitrary argv, remote URI, API policy, or start command exists.
KVM and container cells share this one-shot helper; neither can be activated.
"""
from enum import Enum
import json
import os
from pathlib import PurePosixPath
import platform
import stat
import subprocess
from threading import RLock

from .containers import ContainerCellPolicy, container_nft_rules
from .policy import CellPolicy, PolicyError, _integer
from .render import nft_rules


class IsolationError(RuntimeError):
    pass


class ActivationBlocked(IsolationError):
    pass


class State(str, Enum):
    CONFIGURED = "configurado"
    APPLIED = "aplicado"
    VERIFIED = "verificado"  # Reserved: NEVER produced by this prototype.
    DEGRADED = "degradado"


def _local_root() -> None:
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise IsolationError("requires local Linux root; no privilege escalation supported")
    release = platform.freedesktop_os_release()
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise IsolationError("only Ubuntu 24.04 is supported")


def _trusted_stat(info, *, directory=False):
    expected = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
            or (not directory and info.st_nlink != 1)):
        raise IsolationError("path must be root-owned, non-writable by others and non-symlinked")


def _open_trusted(path: str) -> int:
    """Walk from / using retained no-follow directory descriptors (Linux only)."""
    parts = PurePosixPath(path).parts
    if not parts or parts[0] != "/" or any(p in (".", "..") for p in parts):
        raise IsolationError("absolute canonical managed path required")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        _trusted_stat(os.fstat(directory), directory=True)
        for part in parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=directory)
            os.close(directory)
            directory = child
            _trusted_stat(os.fstat(directory), directory=True)
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                       dir_fd=directory)
        try:
            _trusted_stat(os.fstat(leaf))
            return leaf
        except BaseException:
            os.close(leaf)
            raise
    finally:
        os.close(directory)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate JSON key")
        result[key] = value
    return result


def _load_policy(cell: int):
    _local_root()
    descriptor = _open_trusted(f"/etc/dystopia/isolation/cell-{cell}.json")
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if before.st_size > 16384:
            raise PolicyError("policy exceeds 16 KiB")
        data = stream.read(16385)
        after = os.fstat(stream.fileno())
        if (len(data) != before.st_size or len(data) > 16384
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise PolicyError("policy changed during read")
    document = json.loads(data, object_pairs_hook=_unique_object)
    if type(document) is not dict:
        raise PolicyError("policy object required")
    if document.get("workload") == "container":
        policy = ContainerCellPolicy.from_mapping(document)
    else:
        policy = CellPolicy.from_mapping(document)
    if policy.cell != cell:
        raise PolicyError("policy cell does not match its managed filename")
    return policy


def _install(policy, *, quarantine: bool) -> None:
    _local_root()
    binary = _open_trusted("/usr/sbin/nft")
    try:
        if not os.fstat(binary).st_mode & 0o111:
            raise IsolationError("nft is not executable")
    finally:
        os.close(binary)
    rules = (container_nft_rules(policy, quarantine=quarantine)
             if type(policy) is ContainerCellPolicy
             else nft_rules(policy, quarantine=quarantine))
    for options in (("--check", "--file", "-"), ("--file", "-")):
        # Paths, argv, environment and timeout are fixed, never policy-controlled.
        result = subprocess.run(
            ("/usr/sbin/nft", *options), input=rules, text=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin", "LANG": "C", "LC_ALL": "C"},
            cwd="/", timeout=5, check=False, close_fds=True, start_new_session=True,
        )
        if result.returncode != 0:
            raise IsolationError("nft rejected transaction; no containment claim is possible")


class LocalCellBackend:
    """One-shot policy snapshot loaded ONLY from a fixed root-owned local file.

    A cell is either one KVM guest or one containerized honeypot, never both.
    This is a trusted in-process component, not a sandbox for hostile Python.
    Existing tables are never adopted or replaced, even after controller restart.
    """
    def __init__(self, cell: int):
        _integer(cell, 1, 254)
        self._policy = _load_policy(cell)
        self._state = State.CONFIGURED
        self._detail = "declarative policy loaded; kernel and workload not verified"
        self._stopped = False
        self._lock = RLock()

    @property
    def state(self) -> State:
        return self._state

    @property
    def detail(self) -> str:
        return self._detail

    def apply(self) -> State:
        with self._lock:
            if self._stopped or self._state is not State.CONFIGURED:
                raise IsolationError("one-shot apply requires a fresh configured controller")
            if type(self._policy) is ContainerCellPolicy:
                errors = self._policy.deployment_errors()
                if errors:
                    self._state = State.DEGRADED
                    self._detail = "container policy not deployment-ready: " + "; ".join(errors)
                    raise IsolationError(self._detail)
            try:
                _install(self._policy, quarantine=False)
            except Exception as exc:
                self._state = State.DEGRADED
                self._detail = "apply failed; attempting additive quarantine"
                try:
                    self.quarantine()
                except IsolationError:
                    pass
                raise IsolationError("apply failed; activation prohibited") from exc
            self._state = State.APPLIED
            self._detail = "nft accepted transaction only; connectivity unverified; activation prohibited"
            return self._state

    def quarantine(self) -> State:
        with self._lock:
            self._state = State.DEGRADED
            try:
                _install(self._policy, quarantine=True)
            except Exception as exc:
                self._detail = "quarantine NOT confirmed; existing rules retained; operator required"
                raise IsolationError(self._detail) from exc
            self._detail = "additive drop transaction accepted; kernel containment still unverified"
            return self._state

    def emergency(self) -> State:
        return self.quarantine()

    def stop(self) -> State:
        """Request additive quarantine and stop controller, never remove any rules."""
        with self._lock:
            self._stopped = True
            return self.quarantine()

    def verify(self) -> None:
        self._state = State.DEGRADED
        self._detail = "kernel/topology/workload integration verifier is not implemented"
        raise ActivationBlocked(self._detail)

    def activate(self) -> None:
        # No client boolean, attestation, state assignment or successful apply can bypass this.
        raise ActivationBlocked(
            "ACTIVATION BLOCKED: independent kernel/workload/connectivity verifier missing")
