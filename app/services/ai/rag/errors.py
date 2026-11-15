"""Errores del RAG.

Se distinguen tres situaciones para que el router no las confunda:

- ``RagDisabled``: la capa está apagada por configuración.
- ``RagNotIndexed``: la capa está activa pero todavía no hay memoria.
- ``RagUnavailable``: el modelo o el índice no están disponibles ahora.
"""

from __future__ import annotations


class RagError(RuntimeError):
    """Error base del subsistema RAG."""


class RagDisabled(RagError):
    """El RAG no está habilitado (``NETPULSE_RAG_ENABLED=false``)."""


class RagNotIndexed(RagError):
    """No existe la base de memoria o está vacía."""


class RagUnavailable(RagError):
    """Embeddings, modelo generativo o índice no disponibles."""
