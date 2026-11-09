"""Crea/actualiza el usuario de laboratorio en el volumen de configuración.

Se ejecuta dentro del contenedor `control` como root (una sola vez):
    printf '%s' "$PASSWORD" | docker compose run --rm -T --user 0 \
        -v "$PWD/bootstrap-user.py:/tmp/bootstrap-user.py:ro" \
        control python /tmp/bootstrap-user.py
"""
import os
from pathlib import Path
import sys

import yaml

from app.core.security import hash_password

password = sys.stdin.readline().rstrip("\n")
if len(password) < 12:
    sys.exit("La contraseña debe tener al menos 12 caracteres")

config_dir = Path(os.environ.get("DYSTOPIA_CONTROL_CONFIG", "/srv/local-config"))
config_dir.mkdir(parents=True, exist_ok=True)
path = config_dir / "users.yaml"
path.write_text(
    yaml.safe_dump(
        {
            "users": [
                {
                    "username": "lab",
                    "role": "admin",
                    "password_hash": hash_password(password),
                }
            ]
        },
        sort_keys=False,
    ),
    encoding="utf-8",
)
os.chmod(path, 0o600)
os.chmod(config_dir, 0o750)
for target in (path, config_dir):
    try:
        os.chown(target, 2000, 2000)
    except PermissionError:
        pass
print(f"usuario lab creado en {path}")
