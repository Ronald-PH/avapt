import json
import urllib.request as _urllib
import urllib.error   as _urlerr

from core.config import AI_TIMEOUT_SECS, AI_TEMPERATURE, AI_NUM_PREDICT


class OllamaClient:
    """Thin, dependency-free wrapper around the Ollama /api/generate endpoint."""

    def __init__(self, base_url: str = "http://localhost:11434",
                 model: str = "codellama"):
        self.base_url = base_url.rstrip("/")
        self.model    = model
        self._ok: bool | None = None

    # ── connectivity ──────────────────────────────────────────────────────────

    def is_available(self) -> bool:
        if self._ok is not None:
            return self._ok
        try:
            req = _urllib.Request(f"{self.base_url}/api/tags")
            with _urllib.urlopen(req, timeout=5) as r:
                self._ok = (r.status == 200)
        except Exception:
            self._ok = False
        return self._ok

    def list_models(self) -> list[str]:
        try:
            req = _urllib.Request(f"{self.base_url}/api/tags")
            with _urllib.urlopen(req, timeout=5) as r:
                data = json.loads(r.read())
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    # ── inference ─────────────────────────────────────────────────────────────

    def generate(self, prompt: str, system: str = "") -> str:
        payload = json.dumps({
            "model":  self.model,
            "prompt": prompt,
            "system": system,
            "stream": False,
            "options": {
                "temperature": AI_TEMPERATURE,
                "num_predict": AI_NUM_PREDICT,
            },
        }).encode("utf-8")

        req = _urllib.Request(
            f"{self.base_url}/api/generate",
            data    = payload,
            headers = {"Content-Type": "application/json"},
            method  = "POST",
        )
        try:
            with _urllib.urlopen(req, timeout=AI_TIMEOUT_SECS) as r:
                data = json.loads(r.read())
            if not isinstance(data, dict):
                return ""
            response = data.get("response")
            if response and isinstance(response, str) and response.strip():
                return response
            # Some Ollama models return reasoning or output in alternate fields
            thinking = data.get("thinking")
            if thinking and isinstance(thinking, str) and thinking.strip():
                return thinking
            if "output" in data:
                output = data.get("output")
                if isinstance(output, str) and output.strip():
                    return output
                if isinstance(output, list) and output:
                    first = output[0]
                    if isinstance(first, dict):
                        text = first.get("text") or first.get("response")
                        if isinstance(text, str) and text.strip():
                            return text
            if "choices" in data and isinstance(data["choices"], list) and data["choices"]:
                choice = data["choices"][0]
                if isinstance(choice, dict):
                    text = choice.get("text") or choice.get("message", {}).get("content")
                    if isinstance(text, str) and text.strip():
                        return text
            return ""
        except _urlerr.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise ConnectionError(
                f"Ollama request failed at {self.base_url}: {exc.code} {body}"
            ) from exc
        except _urlerr.URLError as exc:
            raise ConnectionError(f"Ollama unreachable at {self.base_url}: {exc}") from exc
