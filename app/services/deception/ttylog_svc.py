"""Recupera las respuestas del señuelo desde los TTY logs de Cowrie.

Cowrie escribe en el log JSON los comandos recibidos, pero la salida que
devolvió la shell emulada solo queda en la transcripción binaria ``ttylog``.
Este módulo la lee en modo de solo lectura y empareja cada comando con su
salida para que la ficha del atacante muestre qué respondió el señuelo.

El formato del fichero es:

* cabecera de 24 bytes (versión, reservado, timestamp de inicio);
* por cada bloque: ``<magic><reservado><longitud><dirección><timestamp>``
  (24 bytes) seguido del texto. Dirección 1 = entrada, 2 = salida.

Cualquier error de lectura o formato degrada a una lista de respuestas vacías:
la ficha conserva los comandos aunque no haya transcripción disponible.
"""

from __future__ import annotations

import re
import struct
from functools import lru_cache
from pathlib import Path
from typing import Iterable, Optional

MAX_FILE_BYTES = 8_000_000
MAX_OUTPUT_CHARS = 4_000
_HEADER_BYTES = 24
_RECORD_MAGIC = 3

_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_REF = re.compile(r"tty/([0-9a-f]{64})", re.IGNORECASE)
_HASH = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
# Prompt de bash de Cowrie o línea de continuación.
_PROMPT = re.compile(r"^(?:[^\s@]+@[^\s:]+:[^#$]*[#$]|>)\s?")
_CREDENTIAL = re.compile(
    r"(?i)(password|passwd|pwd|token|secret)\s*[=:]\s*[\"']?[^\s\"',;]+"
)


def reference(value: object) -> str:
    """Extrae el nombre (hash) del ttylog desde una ruta o un mensaje."""
    text = str(value or "")
    match = _REF.search(text)
    if match:
        return match.group(1).lower()
    text = text.strip()
    return text.lower() if _HASH.match(text) else ""


def _base_dir() -> Path:
    from app.core.settings import COWRIE_TTY_DIR

    return Path(COWRIE_TTY_DIR)


def resolve(value: object) -> Optional[Path]:
    """Resuelve un hash a un fichero dentro del directorio configurado."""
    name = reference(value)
    if not name:
        return None
    path = _base_dir() / name
    try:
        if not path.is_file():
            return None
        # Defensa ante enlaces simbólicos fuera del directorio de TTY.
        base = _base_dir().resolve()
        if base not in path.resolve().parents:
            return None
    except OSError:
        return None
    return path


@lru_cache(maxsize=32)
def _transcript(path: str, mtime_ns: int, size: int) -> str:
    del mtime_ns, size  # Solo forman parte de la clave de caché.
    try:
        raw = Path(path).read_bytes()[:MAX_FILE_BYTES]
    except OSError:
        return ""
    chunks: list[bytes] = []
    position = _HEADER_BYTES
    while position + _HEADER_BYTES <= len(raw):
        try:
            magic, _reserved, length, direction, _stamp, _usec = struct.unpack(
                "<IIIIII", raw[position:position + _HEADER_BYTES]
            )
        except struct.error:
            break
        if magic != _RECORD_MAGIC or length > MAX_FILE_BYTES:
            break
        data = raw[position + _HEADER_BYTES:position + _HEADER_BYTES + length]
        # Solo la salida del servidor: la entrada del cliente duplica los
        # ecos y desordena el emparejamiento comando → respuesta.
        if direction == 2:
            chunks.append(data)
        position += _HEADER_BYTES + length
    text = b"".join(chunks).decode("utf-8", "replace")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI.sub("", text)
    return _CONTROL.sub("", text)


def _strip_prompt(line: str) -> str:
    return _PROMPT.sub("", line, count=1)


def _find_echo(lines: list[str], start: int, command: str) -> Optional[int]:
    for index in range(max(0, start), len(lines)):
        line = lines[index]
        prompt = bool(_PROMPT.match(line))
        stripped = _strip_prompt(line).strip()
        if prompt and command in stripped:
            return index
        if stripped == command:
            return index
    return None


def _redact(text: str) -> str:
    return _CREDENTIAL.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)


def command_outputs(reference_value: object, commands: Iterable[str]) -> list[str]:
    """Devuelve una salida por comando, en el mismo orden recibido.

    La alineación se apoya en los ecos del terminal y en los prompts que
    imprime la shell falsa. Si un comando no aparece en la transcripción, su
    respuesta queda vacía en lugar de desplazar las siguientes.
    """
    wanted = [str(command).strip() for command in commands]
    path = resolve(reference_value)
    if path is None or not any(wanted):
        return ["" for _ in wanted]
    try:
        stat = path.stat()
    except OSError:
        return ["" for _ in wanted]
    text = _transcript(str(path), stat.st_mtime_ns, stat.st_size)
    if not text:
        return ["" for _ in wanted]
    lines = text.splitlines()
    upcoming = {command for command in wanted if command}
    outputs: list[str] = []
    cursor = 0
    for command in wanted:
        if not command:
            outputs.append("")
            continue
        found = _find_echo(lines, cursor, command)
        if found is None:
            outputs.append("")
            continue
        chunk: list[str] = []
        index = found + 1
        while index < len(lines):
            line = lines[index]
            if _PROMPT.match(line):
                break
            stripped = _strip_prompt(line).strip()
            if stripped.startswith(">"):
                stripped = stripped[1:].strip()
            if not stripped:
                if chunk:
                    chunk.append("")
                index += 1
                continue
            # Los ecos de comandos posteriores no son respuesta del señuelo.
            if stripped in upcoming:
                index += 1
                continue
            chunk.append(_strip_prompt(line).rstrip())
            index += 1
        while chunk and not chunk[-1].strip():
            chunk.pop()
        outputs.append(_redact("\n".join(chunk).strip())[:MAX_OUTPUT_CHARS])
        cursor = index
    return outputs
