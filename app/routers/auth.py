"""NetPulse — Router de Autenticación.

Endpoints:
- POST /api/auth/login  — validar credenciales, devolver JWT
- GET  /api/auth/me     — info del usuario autenticado
"""

import hashlib
import yaml
from runtime.localfiles import read_private
from app.core.settings import CONFIG_DIR

from fastapi import APIRouter, Depends, HTTPException, Request

from app.core.limiter import limiter

from app.core.security import (
    create_access_token,
    verify_password,
)
from app.models.schemas import LoginRequest, TokenResponse, UserInfo, UserRole
from app.middleware.auth import JWTBearer
from app.middleware.rbac import get_current_user
from app.services.metrics_svc import netpulse_auth_total

router = APIRouter(prefix="/api/auth", tags=["Auth"])

# ── Carga de usuarios ─────────────────────────────────────────

USERS_FILE = CONFIG_DIR / "users.yaml"
_users_cache: dict[str, dict] = {}


def _load_users() -> dict[str, dict]:
    """Carga usuarios desde config/users.yaml y hashea contraseñas."""
    users: dict[str, dict] = {}
    if not USERS_FILE.exists():
        return users

    data = yaml.safe_load(read_private(USERS_FILE)) or {}

    for u in data.get("users", []):
        username = u.get("username", "")
        if not username:
            continue
        # Si no hay hash almacenado, generarlo desde plain_password
        pwd_hash = u.get("password_hash") or ""  # No plaintext-password migration at login.
        users[username] = {
            "username": username,
            "role": u.get("role", "viewer"),
            "password_hash": pwd_hash,
        }

    return users


def _get_users() -> dict[str, dict]:
    """Devuelve el caché de usuarios, cargándolo si es necesario."""
    global _users_cache
    _users_cache = _load_users()  # Reflect revocation across workers immediately.
    return _users_cache


# ── Endpoints ─────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")  # Anti brute-force: máx 5 intentos/min por IP
def login(request: Request, body: LoginRequest):
    """Inicia sesión con usuario y contraseña.

    Devuelve un token JWT con claims: sub (username), role.
    Límite: 5 intentos por minuto por IP (anti fuerza bruta).
    """
    users = _get_users()
    user = users.get(body.username)

    if not user or not verify_password(body.password, user["password_hash"]):
        netpulse_auth_total.labels(status="failure").inc()
        raise HTTPException(
            status_code=401,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generar token JWT
    token = create_access_token(
        data={
            "sub": user["username"],
            "role": user["role"],
            "ver": hashlib.sha256(user["password_hash"].encode()).hexdigest(),
        }
    )

    netpulse_auth_total.labels(status="success").inc()
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserInfo, dependencies=[Depends(JWTBearer())])
def get_me(user: dict = Depends(get_current_user)):
    """Devuelve la información del usuario autenticado.

    Requiere token JWT válido en el header Authorization.
    """
    return UserInfo(
        username=user["sub"],
        role=UserRole(user["role"]),
    )
