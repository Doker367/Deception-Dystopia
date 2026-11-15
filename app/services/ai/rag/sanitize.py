"""Redacción previa al índice y al prompt.

Todo texto capturado por un señuelo pasa por aquí antes de guardarse en el
índice o de enviarse a un modelo local. La redacción no sustituye al control
de acceso: es una segunda barrera para que credenciales, tokens y claves
privadas no queden persistidas en la memoria del RAG.
"""

from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|"
            r"bearer|community|snmp[_ ]?ro|enable[_ ]?password)\s*[:=]\s*\S+"
        ),
        r"\1=***",
    ),
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer ***"),
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "***PRIVATE KEY***",
    ),
    # user:password@host en URLs de conexión.
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), r"\1***@"),
    # Contraseñas pasadas como argumento de línea de comandos.
    (re.compile(r"(?i)(\s-p\s|\s--password[ =])\S+"), r"\1***"),
)


def sanitize(text: str, max_len: int = 4000) -> str:
    """Normaliza, redacta secretos y recorta un texto libre.

    Args:
        text: contenido crudo (log, comando, nota).
        max_len: longitud máxima del resultado, incluido el sufijo ``…``.

    Returns:
        Texto sin secuencias de control ni credenciales evidentes.
    """
    if not text:
        return ""
    out = _ANSI.sub("", str(text))
    out = _CONTROL.sub(" ", out)
    for pattern, replacement in _REDACTIONS:
        out = pattern.sub(replacement, out)
    out = re.sub(r"[ \t]{2,}", " ", out)
    out = re.sub(r"\n{3,}", "\n\n", out).strip()
    if max_len > 0 and len(out) > max_len:
        out = out[: max_len - 1].rstrip() + "…"
    return out
