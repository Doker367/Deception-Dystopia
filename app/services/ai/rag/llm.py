"""Cliente del modelo generativo local (API chat completions de llama.cpp)."""

from __future__ import annotations

from typing import Optional

from app.services.ai.rag.errors import RagUnavailable


class HttpLLM:
    """Una llamada sin streaming; el operador espera la respuesta completa."""

    def __init__(
        self,
        url: str,
        model: str,
        *,
        api_key: str = "",
        timeout: float = 120.0,
        max_tokens: int = 900,
        disable_thinking: bool = True,
    ) -> None:
        self.url = url
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.max_tokens = max_tokens
        self.disable_thinking = disable_thinking

    def complete(self, system: str, user: str, *, temperature: float = 0.1) -> dict:
        """Devuelve ``{"text", "model", "usage"}`` o lanza ``RagUnavailable``."""
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "temperature": temperature,
            "top_p": 0.9,
            "max_tokens": self.max_tokens,
            "stream": False,
        }
        if self.disable_thinking:
            # Plantillas Qwen: evita que el razonamiento consuma max_tokens y
            # que el texto de análisis se confunda con la respuesta.
            payload["chat_template_kwargs"] = {"enable_thinking": False}
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
            raise RagUnavailable(f"modelo generativo no disponible: {str(exc)[:180]}") from exc

        choices = data.get("choices") if isinstance(data, dict) else None
        text = ""
        if isinstance(choices, list) and choices:
            message = choices[0].get("message") or {}
            text = str(message.get("content") or "")
            if not text:
                # Algunos servidores separan la cadena de razonamiento.
                text = str(message.get("reasoning_content") or "")
        if not text.strip():
            raise RagUnavailable("el modelo devolvió una respuesta vacía")
        return {
            "text": text.strip(),
            "model": str(data.get("model") or self.model),
            "usage": data.get("usage") or {},
        }

    def health(self) -> dict:
        return {"reachable": None, "model": self.model, "url": self.url}


def get_llm() -> Optional[HttpLLM]:
    """Construye el cliente según la configuración vigente."""
    from app.core import settings

    if not settings.RAG_LLM_URL:
        return None
    return HttpLLM(
        url=settings.RAG_LLM_URL,
        model=settings.RAG_LLM_MODEL,
        api_key=settings.RAG_LLM_API_KEY,
        timeout=settings.RAG_LLM_TIMEOUT,
        max_tokens=settings.RAG_LLM_MAX_TOKENS,
        disable_thinking=settings.RAG_LLM_DISABLE_THINKING,
    )
