"""Utilidades vectoriales sin dependencias externas.

Los vectores se normalizan (L2) antes de guardarse, así la similitud coseno
se reduce a un producto escalar. Se empaquetan como ``float32`` para no
inflar SQLite con JSON.
"""

from __future__ import annotations

import math
from array import array
from typing import Iterable, Sequence

Vector = Sequence[float]


def normalize(values: Iterable[float]) -> tuple[list[float], float]:
    """Devuelve ``(vector_unitario, norma_original)``."""
    vec = [float(value) for value in values]
    norm = math.sqrt(math.sumprod(vec, vec)) if vec else 0.0
    if not norm:
        return [0.0 for _ in vec], 0.0
    return [value / norm for value in vec], norm


def pack(values: Vector) -> bytes:
    """Serializa un vector como ``float32`` little-endian nativo."""
    return array("f", values).tobytes()


def unpack(blob: bytes) -> list[float]:
    """Reconstruye un vector desde su representación binaria."""
    vec = array("f")
    vec.frombytes(blob)
    return vec.tolist()


def dot_unit(a: Vector, b: Vector) -> float:
    """Producto escalar de dos vectores ya normalizados."""
    if len(a) != len(b):
        return 0.0
    return math.sumprod(a, b)
