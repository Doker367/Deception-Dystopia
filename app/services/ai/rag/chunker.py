"""Troceado de texto para el índice del RAG.

Dos modos:

- ``chunk_text``: texto libre (comandos, notas, resúmenes de eventos) con
  solape para no perder contexto en la frontera.
- ``chunk_markdown``: documentación, conservando la ruta de encabezados para
  que cada fragmento sea citable.
"""

from __future__ import annotations

import re

_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def estimate_tokens(text: str) -> int:
    """Estimación barata (4 caracteres por token) para presupuestar el prompt."""
    return max(1, len(text or "") // 4)


def chunk_text(text: str, size: int = 900, overlap: int = 120, min_len: int = 40) -> list[str]:
    """Divide texto libre en fragmentos de hasta ``size`` caracteres.

    Respeta párrafos y frases cuando puede; si una unidad sigue siendo mayor
    que ``size`` la corta de forma dura. El solape se toma del final del
    fragmento anterior y nunca supera ``overlap`` caracteres.
    """
    if not text:
        return []
    size = max(200, size)
    overlap = max(0, min(overlap, size // 2))
    clean = re.sub(r"[ \t]+", " ", str(text))
    clean = re.sub(r"\n{3,}", "\n\n", clean).strip()
    if not clean:
        return []

    chunks: list[str] = []
    current = ""
    for unit in _units(clean, size):
        if not current:
            current = unit
            continue
        separator = "\n" if "\n" in unit or unit.startswith(("- ", "* ")) else " "
        if len(current) + len(separator) + len(unit) <= size:
            current = f"{current}{separator}{unit}"
            continue
        chunks.append(current)
        tail = _tail(current, overlap)
        if tail and len(tail) + 1 + len(unit) <= size:
            current = f"{tail}\n{unit}"
        else:
            current = unit
    if current:
        chunks.append(current)

    return [chunk.strip() for chunk in chunks if len(chunk.strip()) >= max(1, min_len)]


def chunk_markdown(text: str, size: int = 900, overlap: int = 120) -> list[dict]:
    """Trocea Markdown y devuelve ``{"text", "heading"}`` por fragmento."""
    if not text:
        return []
    sections: list[tuple[str, str]] = []
    path: list[str] = []
    buffer: list[str] = []

    def flush() -> None:
        body = "\n".join(buffer).strip()
        heading = " > ".join(path)
        if body:
            sections.append((heading, body))
        buffer.clear()

    for line in str(text).splitlines():
        match = _HEADING.match(line)
        if match:
            flush()
            level = len(match.group(1))
            title = match.group(2).strip()
            path = path[: level - 1] + [title]
        else:
            buffer.append(line)
    flush()

    out: list[dict] = []
    for heading, body in sections:
        for piece in chunk_text(body, size=size, overlap=overlap, min_len=1):
            out.append({"text": piece, "heading": heading})
    return out


def _units(text: str, size: int):
    """Genera unidades atómicas: párrafos, frases y cortes duros."""
    for block in text.split("\n\n"):
        block = block.strip()
        if not block:
            continue
        if len(block) <= size:
            yield block
            continue
        for sentence in _SENTENCE.split(block):
            sentence = sentence.strip()
            if not sentence:
                continue
            if len(sentence) <= size:
                yield sentence
            else:
                for start in range(0, len(sentence), size):
                    piece = sentence[start : start + size].strip()
                    if piece:
                        yield piece


def _tail(text: str, overlap: int) -> str:
    """Último tramo del texto, alineado a una frontera de palabra."""
    if overlap <= 0 or not text:
        return ""
    tail = text[-overlap:]
    cut = tail.find(" ")
    if cut > 0:
        tail = tail[cut + 1 :]
    return tail.strip()
