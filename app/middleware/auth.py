"""NetPulse — JWT Bearer authentication middleware.

Provee JWTBearer, una dependencia FastAPI que extrae y valida
el token JWT del header Authorization en cada request.
"""

from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.security import verify_token


class JWTBearer(HTTPBearer):
    """Dependencia FastAPI que valida tokens JWT Bearer.

    Uso:
        @router.get("/protegido", dependencies=[Depends(JWTBearer())])
        def endpoint_protegido(...):
            ...
    """

    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)

    async def __call__(self, request: Request) -> HTTPAuthorizationCredentials:
        """Extrae y valida el token, devuelve credenciales o lanza 401."""
        credentials: HTTPAuthorizationCredentials | None = await super().__call__(request)

        if credentials is None:
            raise HTTPException(
                status_code=401,
                detail="Token de autorización requerido",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=403,
                detail="Esquema de autenticación inválido (se requiere Bearer)",
            )

        token = credentials.credentials

        # Soporte de API keys (np_...) para automatización
        if token.startswith("np_"):
            from app.services.security import api_keys_svc
            key_info = api_keys_svc.validate_api_key(token)
            if key_info is None:
                raise HTTPException(
                    status_code=401,
                    detail="API key inválida o revocada",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            request.state.user = {
                "sub": f"apikey:{key_info['name']}",
                "role": key_info.get("role", "viewer"),
                "api_key_id": key_info.get("id"),
            }
            return credentials

        payload = verify_token(token)

        if payload is None:
            raise HTTPException(
                status_code=401,
                detail="Token inválido o expirado",
                headers={"WWW-Authenticate": "Bearer"},
            )

        import hashlib
        from app.routers.auth import _get_users
        subject = payload.get("sub")
        if not isinstance(subject, str):
            raise HTTPException(401, "Token inválido o expirado")
        user = _get_users().get(subject)
        if (not user or payload.get("role") != user["role"] or
                payload.get("ver") != hashlib.sha256(user["password_hash"].encode()).hexdigest()):
            raise HTTPException(401, "User changed or token revoked")
        request.state.user = payload
        return credentials
