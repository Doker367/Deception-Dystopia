"""Offline, explicit Ubuntu 24.04 installer. Plan never writes or runs commands.

Network creation and cell activation are deliberately NOT installer operations.
A reviewed, preinstalled release+venv and hash-locked wheel bundle are required.
"""
import argparse
import grp
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import pwd
import re
import secrets
import stat
import subprocess

from runtime.localfiles import create_private, read_private

ACCOUNTS = ("dystopia-control", "dystopia-ingest", "dystopia-sensor", "dystopia-query")
IFACE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}\Z")
RELEASE = Path("/opt/dystopia/current")


def validate_config(data):
    required = {"version", "management_interface", "management_network", "deception_interface",
                "deception_network", "protected_networks", "control_bind", "recovery"}
    if not isinstance(data, dict) or set(data) != required or type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("invalid installation schema")
    for key in ("management_interface", "deception_interface"):
        if not isinstance(data[key], str) or not IFACE.fullmatch(data[key]) or data[key] == "lo":
            raise ValueError("explicit non-loopback interfaces required")
    if data["management_interface"] == data["deception_interface"]:
        raise ValueError("management and deception interfaces must differ")
    mgmt = ipaddress.ip_network(data["management_network"], strict=True)
    deception = ipaddress.ip_network(data["deception_network"], strict=True)
    protected = [ipaddress.ip_network(n, strict=True) for n in data["protected_networks"]]
    if not protected or mgmt not in protected:
        raise ValueError("protected networks must explicitly include management")
    if any(n.version == deception.version and n.overlaps(deception) for n in protected):
        raise ValueError("deception overlaps protected networks")
    # Initial installer only binds loopback. Explicit remote TLS is a separate change.
    if data["control_bind"] != "127.0.0.1":
        raise ValueError("initial installation supports loopback management only")
    if not isinstance(data["recovery"], str) or not 16 <= len(data["recovery"]) <= 1024:
        raise ValueError("document a tested console/recovery mechanism")
    return dict(data)


def plan(config):
    config = validate_config(config)
    return {"mode": "plan", "platform": "Ubuntu Server 24.04 LTS",
            "management_interface": config["management_interface"],
            "deception_interface": config["deception_interface"],
            "bind": config["control_bind"], "create_service_users": list(ACCOUNTS),
            "enable_and_start_after_local_bootstrap": ["dystopia-control.service"],
            "write_units": ["dystopia-"+role+".service" for role in ("control","ingest","sensor","processor","query")]
             + ["dystopia-query.socket"],
            "write_if_absent": ["/etc/dystopia/install.json", "/etc/dystopia/control.env"],
            "create_directories": ["/etc/dystopia", "/var/lib/dystopia", "/var/lib/dystopia/{control,ingest,sensor}",
                                   "/var/lib/dystopia/control/{config,audit,deception}"],
            "ownership": "fchown newly created service directories only; reject unexpected existing owners",
            "systemd_daemon_reload": True, "network_changes": [],
            "sensors": "disabled", "activation": "blocked",
            "preserve": ["existing secrets", "existing config", "users", "event data"],
            "requires": ["root", "Ubuntu 24.04", "explicit apply", "verified offline release and lock",
                         "existing interfaces", "local administrator bootstrap", "recovery console"]}


def _command(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})


def verify_bundle(bundle):
    """Manifest is an operator-reviewed trust root, not a claim of publisher signature.

    hashes.json maps relative artifact paths to SHA256. It must cover requirements.lock
    and every wheel. Installer does not download/build/install Python packages.
    """
    bundle = Path(bundle)
    manifest = json.loads((bundle / "hashes.json").read_bytes())
    if not isinstance(manifest, dict) or "requirements.lock" not in manifest:
        raise ValueError("reviewed lock and artifact hashes required")
    for name, digest in manifest.items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid artifact manifest")
        candidate = bundle / relative
        if candidate.is_symlink() or candidate.resolve().parent != bundle.resolve():
            raise ValueError("artifact must be a regular direct child")
        if not candidate.is_file():
            raise ValueError("missing artifact")
        hasher = hashlib.sha256()
        with candidate.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024*1024), b""):
                hasher.update(chunk)
        if hasher.hexdigest() != digest:
            raise ValueError("artifact digest mismatch")
    lock = (bundle / "requirements.lock").read_text()
    # Require pinned hash-checked logical lines; pip's offline --require-hashes is
    # additionally required when the administrator builds the immutable venv.
    lines = lock.replace("\\\n", " ").splitlines()
    if ({p.name for p in bundle.glob("*.whl")} != {n for n in manifest if n.endswith(".whl")}):
        raise ValueError("all wheels must be covered by the reviewed manifest")
    if not any(line.strip() and not line.lstrip().startswith("#") for line in lines) or not any(name.endswith(".whl") for name in manifest):
        raise ValueError("empty wheel bundle")
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#") and not re.fullmatch(
                r"[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[A-Za-z0-9_.+!-]+(?:\s+--hash=sha256:[a-f0-9]{64})+", line):
            raise ValueError("lock must contain exact versions and real SHA256 hashes")
    return True


def _directory_at(parent, name, uid, gid, mode, create):
    made = False
    if create:
        try:
            os.mkdir(name, mode, dir_fd=parent)
            made = True
        except FileExistsError:
            pass
    try:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    except FileNotFoundError:
        if not create:
            return None
        raise
    try:
        info = os.fstat(fd)
        if made:
            if info.st_uid != 0:
                raise PermissionError("new directory replaced during provisioning")
            os.fchown(fd, uid, gid)
            os.fchmod(fd, mode)
        elif info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
            raise PermissionError("unexpected existing directory owner or permissions")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _root_directory(path, mode=0o711, create=False):
    """Trusted root-owned ancestor walk; caller owns returned descriptor."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute installation path required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise PermissionError("installation ancestors must be root-owned and immutable to services")
        return _directory_at(fd, path.name, 0, 0, mode, create)
    finally:
        os.close(fd)


def _service_tree(account, role, create=False):
    parent = _root_directory("/var/lib/dystopia", create=False)
    if parent is None:
        return
    directory = None
    try:
        if role == "ingest":
            try:
                bridge_group = grp.getgrnam("dystopia-query").gr_gid
            except KeyError:
                raise RuntimeError("query group must be provisioned before ingest directory migration") from None
            # Traverse-only group: no directory listing and no access to 0600 secrets.
            directory = _directory_at(parent, role, account.pw_uid, bridge_group, 0o710, create)
        else:
            directory = _directory_at(parent, role, account.pw_uid, account.pw_gid, 0o700, create)
        if directory is not None and role == "control":
            for name in ("config", "audit", "deception"):
                child = _directory_at(directory, name, account.pw_uid, account.pw_gid, 0o700, create)
                if child is not None:
                    os.close(child)
    finally:
        if directory is not None:
            os.close(directory)
        os.close(parent)


def _account(user):
    try:
        account = pwd.getpwnam(user)
    except KeyError:
        return None
    if (account.pw_shell != "/usr/sbin/nologin" or account.pw_dir != "/nonexistent"
            or account.pw_uid < 100 or account.pw_gid < 100
            or grp.getgrgid(account.pw_gid).gr_name != user
            or set(grp.getgrgid(account.pw_gid).gr_mem) - {user}
            or set(os.getgrouplist(user, account.pw_gid)) != {account.pw_gid}
            or any(p.pw_name != user and (p.pw_gid == account.pw_gid or p.pw_uid == account.pw_uid)
                   for p in pwd.getpwall())):
        raise RuntimeError("unexpected pre-existing service account or groups")
    return account


def _environment_valid(path):
    text = read_private(path, expected_uid=0).decode()
    rows = text.splitlines()
    if len(rows) != 4:
        raise ValueError("existing environment needs explicit repair")
    entries = dict(line.split("=",1) for line in rows)
    if (set(entries) != {"NETPULSE_JWT_SECRET", "DYSTOPIA_CONTROL_STATE", "DYSTOPIA_CONTROL_CONFIG", "NETPULSE_ENV"}
            or not re.fullmatch(r"[A-Za-z0-9_-]{64}", entries["NETPULSE_JWT_SECRET"])
            or entries["DYSTOPIA_CONTROL_STATE"] != "/var/lib/dystopia/control"
            or entries["DYSTOPIA_CONTROL_CONFIG"] != "/var/lib/dystopia/control/config"
            or entries["NETPULSE_ENV"] != "production"):
        raise ValueError("existing environment differs; never overwrite secrets silently")


def preflight(config, bundle):
    validate_config(config)
    if config["recovery"].startswith("EJEMPLO:"):
        raise RuntimeError("replace the recovery example with an authorized tested procedure")
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise RuntimeError("apply requires local root on Ubuntu Server 24.04")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    if release.get("ID", "").strip('"') != "ubuntu" or release.get("VERSION_ID", "").strip('"') != "24.04":
        raise RuntimeError("unsupported platform")
    for key in ("management_interface", "deception_interface"):
        if not (Path("/sys/class/net") / config[key]).exists():
            raise RuntimeError("configured interface does not exist")
    addresses = json.loads(_command(["/usr/sbin/ip", "-json", "address", "show", "dev", config["management_interface"]]).stdout)
    net = ipaddress.ip_network(config["management_network"])
    ips = [ipaddress.ip_address(a["local"]) for interface in addresses for a in interface.get("addr_info", [])]
    if not any(ip.version == net.version and ip in net for ip in ips):
        raise RuntimeError("management interface has no address in declared network")
    if not Path("/dev/kvm").exists() or not Path("/usr/sbin/nft").is_file() or not Path("/usr/bin/virsh").is_file():
        raise RuntimeError("KVM, nftables and libvirt must be provisioned by administrator")
    verify_bundle(bundle)
    # This installer consumes, never mutates or downloads, the verified release.
    if not (RELEASE / "runtime/cli.py").is_file() or not Path("/opt/dystopia/venv/bin/python").is_file():
        raise RuntimeError("reviewed release and offline venv must be provisioned first")
    if RELEASE.is_symlink():
        raise RuntimeError("release must be an immutable directory, not a symlink")
    for root in (RELEASE, Path("/opt/dystopia/venv")):
        descriptor = _root_directory(root, mode=0o755, create=False)
        if descriptor is None:
            raise RuntimeError("missing immutable release directory")
        os.close(descriptor)
        for path in (root, *root.rglob("*")):
            info = path.lstat()
            if info.st_uid != 0 or (not path.is_symlink() and info.st_mode & 0o022) or (path.is_symlink() and root == RELEASE):
                raise PermissionError("release/toolchain must be root-owned and not group/world writable")
            if path.is_symlink():
                resolved = path.resolve(strict=True)
                for target in (resolved, *resolved.parents):
                    target_info = target.stat()
                    if target_info.st_uid != 0 or target_info.st_mode & 0o022:
                        raise PermissionError("toolchain symlink escapes to an untrusted path")
    # Verify the administrator's actual release source hashes as well as wheels.
    source_hashes = verify_release(RELEASE)
    verify_release(Path("/opt/dystopia/venv"))
    lock_digest = hashlib.sha256((Path(bundle) / "requirements.lock").read_bytes()).hexdigest()
    installed_lock = Path("/opt/dystopia/venv/installed-lock.sha256").read_text().strip()
    if installed_lock != lock_digest:
        raise RuntimeError("reviewed venv does not attest to this exact dependency lock")
    # Validate all existing destinations/accounts/units BEFORE the first mutation.
    for directory, mode in (("/etc/dystopia", 0o711), ("/var/lib/dystopia", 0o711),
                            ("/etc/systemd/system", 0o755)):
        descriptor = _root_directory(directory, mode=mode)
        if descriptor is not None:
            os.close(descriptor)
    for role, user in zip(("control", "ingest", "sensor"), ACCOUNTS[:3]):
        account = _account(user)
        target = Path("/var/lib/dystopia") / role
        if account is None and (target.exists() or target.is_symlink()):
            raise PermissionError("existing service tree without expected account")
        if account:
            _service_tree(account, role)
    # The query identity has no writable state tree or supplementary groups.
    _account("dystopia-query")
    config_file = Path("/etc/dystopia/install.json")
    if config_file.exists() or config_file.is_symlink():
        if json.loads(read_private(config_file, expected_uid=0)) != config:
            raise RuntimeError("existing configuration differs; explicit migration required")
    env_file = Path("/etc/dystopia/control.env")
    if env_file.exists() or env_file.is_symlink():
        _environment_valid(env_file)
    units = {}
    for name in ("dystopia-control.service", "dystopia-ingest.service", "dystopia-sensor.service",
                 "dystopia-processor.service", "dystopia-query.service", "dystopia-query.socket"):
        content = (RELEASE / "deploy/systemd" / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != source_hashes["deploy/systemd/" + name]:
            raise RuntimeError("unit changed after release validation")
        units[name] = content
        target = Path("/etc/systemd/system") / name
        if (target.exists() or target.is_symlink()) and read_private(target, expected_uid=0) != content:
            raise RuntimeError("existing unit differs; explicit migration required")
        for base in ("/etc/systemd/system", "/run/systemd/system"):
            if (Path(base) / (name + ".d")).exists():
                raise RuntimeError("existing drop-ins require separate operator review, not reinstall")
    users = Path("/var/lib/dystopia/control/config/users.yaml")
    if users.exists() or users.is_symlink():
        _validate_users(users)
    return units


def _validate_users(path):
    account = _account("dystopia-control")
    if account is None:
        raise PermissionError("missing control account")
    import yaml
    data = yaml.safe_load(read_private(path, expected_uid=account.pw_uid))
    if not isinstance(data, dict) or not isinstance(data.get("users"), list) or not all(isinstance(u,dict) for u in data["users"]):
        raise ValueError("invalid existing user store")
    if not any(u.get("role") == "admin" and re.fullmatch(r"\$2[aby]\$12\$[./A-Za-z0-9]{53}", u.get("password_hash", "")) for u in data.get("users", [])):
        raise ValueError("local administrator must be provisioned before management starts")


def verify_release(root):
    root = Path(root)
    manifest = json.loads((root / "release-hashes.json").read_text())
    files = {str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and p.name != "release-hashes.json"}
    if set(manifest) != files:
        raise ValueError("release manifest must cover every shipped file")
    for name in files:
        if hashlib.sha256((root / name).read_bytes()).hexdigest() != manifest[name]:
            raise ValueError("release source digest mismatch")
    return manifest


def apply(config, bundle, confirmation):
    if confirmation != "APPLY-MANAGEMENT-ONLY":
        raise PermissionError("explicit management-only confirmation required")
    units = preflight(config, bundle)  # keep verified unit bytes; never reread mutable source
    etc, state = Path("/etc/dystopia"), Path("/var/lib/dystopia")
    for path in (etc, state):
        descriptor = _root_directory(path, create=True)
        os.close(descriptor)
    wanted = json.dumps(config, sort_keys=True, indent=2).encode()
    existing = etc / "install.json"
    for user in ACCOUNTS:
        if _account(user) is None:
            _command(["/usr/sbin/useradd", "--system", "--user-group", "--home-dir", "/nonexistent",
                      "--no-create-home", "--shell", "/usr/sbin/nologin", user])
    for role, user in zip(("control", "ingest", "sensor"), ACCOUNTS[:3]):
        _service_tree(_account(user), role, create=True)
    control = state / "control"
    create_private(existing, wanted)
    environment = ("NETPULSE_JWT_SECRET=" + secrets.token_urlsafe(48) + "\n"
                   "DYSTOPIA_CONTROL_STATE=/var/lib/dystopia/control\n"
                   "DYSTOPIA_CONTROL_CONFIG=/var/lib/dystopia/control/config\n"
                   "NETPULSE_ENV=production\n")
    create_private(etc / "control.env", environment.encode())
    for name, content in units.items():
        target = Path("/etc/systemd/system") / name
        if target.exists() and read_private(target) != content:
            raise RuntimeError("existing systemd unit differs; explicit migration required")
        create_private(target, content)
    # systemd can read private root-owned units; no sensor/ingest auto-enablement.
    _command(["/usr/bin/systemctl", "daemon-reload"])
    users = control / "config/users.yaml"
    if not users.exists():
        return {"state": "configured", "management_started": False,
                "next": "bootstrap administrator locally as dystopia-control, then reapply"}
    _validate_users(users)
    _command(["/usr/bin/systemctl", "enable", "--now", "dystopia-control.service"])
    return diagnose()


def diagnose():
    try:
        state = _command(["/usr/bin/systemctl", "is-active", "dystopia-control.service"]).stdout.strip()
    except subprocess.CalledProcessError as exc:
        # systemctl uses nonzero for inactive/failed/unknown; keep that diagnostic.
        state = (exc.stdout or "unknown").strip()
        if state not in {"inactive", "failed", "unknown", "activating", "deactivating"}:
            state = "diagnostic_error"
    return {"management": state, "network_changed": False, "containment": "not_verified",
            "sensors_started_by_installer": False}


def guided_config():
    """Collect explicit networks without guessing interfaces or modifying files."""
    print("Solo plan/gestión. No se crearán redes ni arrancarán sensores.")
    return validate_config({
        "version": 1,
        "management_interface": input("Interfaz de gestión existente: ").strip(),
        "management_network": input("Subred de gestión (CIDR exacto): ").strip(),
        "deception_interface": input("Interfaz deception distinta: ").strip(),
        "deception_network": input("Subred deception (CIDR exacto): ").strip(),
        "protected_networks": input("Redes protegidas IPv4/IPv6, incluida gestión (separadas por coma): ").replace(" ", "").split(","),
        "control_bind": "127.0.0.1",
        "recovery": input("Consola/recuperación probada y responsable: ").strip(),
    })


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--config", type=Path)
    source.add_argument("--guided", action="store_true")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--plan", "--dry-run", dest="dry_run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--diagnose", action="store_true")
    p.add_argument("--bundle", type=Path)
    p.add_argument("--confirm")
    args = p.parse_args(argv)
    config = guided_config() if args.guided else validate_config(json.loads(args.config.read_text()))
    if args.apply:
        if not args.bundle:
            p.error("a reviewed offline bundle is required")
        result = apply(config, args.bundle, args.confirm)
    elif args.diagnose:
        result = diagnose()
    else:
        result = plan(config)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
