"""Cliente de embeddings servido por llama.cpp (API OpenAI-compatible).

No hay dependencia de un SDK: una petición HTTP por lote. Si el servicio no
responde, el RAG degrada a búsqueda léxica en lugar de inventar resultados.
"""

from __future__ import annotations

from typing import Sequence

from app.services.ai.rag.errors import RagUnavailable


class HttpEmbedder:
    """Embeddings multilingües contra ``/v1/embeddings``."""

    def __init__(
        self,
        url: str,
        model: str,
        *,
        api_key: str = "",
        timeout: float = 30.0,
        dim: int = 0,
        batch: int = 16,
    ) -> None:
        self.url = url
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.dim = dim
        self.batch = max(1, batch)

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        """Convierte textos en vectores, en lotes, validando la dimensión."""
        if not texts:
            return []
        out: list[list[float]] = []
        for start in range(0, len(texts), self.batch):
            out.extend(self._embed_batch(list(texts[start : start + self.batch])))
        for vec in out:
            if self.dim and len(vec) != self.dim:
                raise RagUnavailable(
                    f"dimensión de embedding {len(vec)} != NETPULSE_RAG_EMBED_DIM={self.dim}"
                )
        return out

    def health(self) -> dict:
        """Prueba real de extremo a extremo (una llamada diminuta)."""
        try:
            vec = self.embed(["salud"])[0]
        except Exception as exc:  # noqa: BLE001
            return {"reachable": False, "error": str(exc)[:200]}
        return {"reachable": True, "dim": len(vec), "model": self.model}

    def _embed_batch(self, batch: list[str]) -> list[list[float]]:
        payload = {"model": self.model, "input": [text or " " for text in batch]}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        try:
            import httpx

            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(self.url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
        except Exception as exc:  # noqa: BLE001
            raise RagUnavailable(f"embeddings no disponibles: {str(exc)[:180]}") from exc

        items = data.get("data") if isinstance(data, dict) else None
        if isinstance(items, list) and items:
            ordered = sorted(items, key=lambda item: int(item.get("index", 0)))
            vectors = [list(item.get("embedding") or []) for item in ordered]
        else:
            vectors = _native_vectors(data)
        if len(vectors) != len(batch) or any(not vec for vec in vectors):
            raise RagUnavailable("respuesta de embeddings incompleta o vacía")
        return vectors


def _native_vectors(data: object) -> list[list[float]]:
    """Acepta también la forma nativa de llama.cpp: ``[{"embedding": [...]}]``."""
    if not isinstance(data, list):
        return []
    vectors: list[list[float]] = []
    for item in data:
        if isinstance(item, dict):
            vectors.append(list(item.get("embedding") or []))
        elif isinstance(item, list):
            vectors.append([float(value) for value in item])
    return vectors


def get_embedder() -> HttpEmbedder:
    """Construye el embedder según la configuración vigente."""
    from app.core import settings

    return HttpEmbedder(
        url=settings.RAG_EMBED_URL,
        model=settings.RAG_EMBED_MODEL,
        timeout=settings.RAG_EMBED_TIMEOUT,
        dim=settings.RAG_EMBED_DIM,
        batch=settings.RAG_EMBED_BATCH,
    )
