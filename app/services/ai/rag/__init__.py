"""RAG local de Dystopia: memoria de ataques y documentación.

La fachada pública es ``service``. Los módulos internos se pueden probar de
forma aislada inyectando un embedder y un LLM falsos.
"""

from app.services.ai.rag.errors import (
    RagDisabled,
    RagError,
    RagNotIndexed,
    RagUnavailable,
)
from app.services.ai.rag.service import (
    ack,
    ask,
    feedback,
    findings,
    index,
    is_enabled,
    metrics,
    scan,
    search,
    status,
)

__all__ = [
    "RagDisabled",
    "RagError",
    "RagNotIndexed",
    "RagUnavailable",
    "ack",
    "ask",
    "feedback",
    "findings",
    "index",
    "is_enabled",
    "metrics",
    "scan",
    "search",
    "status",
]
