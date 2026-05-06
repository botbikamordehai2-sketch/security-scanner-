"""
DeepSeek AI — Unified Module for all Agents.
Single entry point for DeepSeek API calls used by Orchestrator, Tech Pulse, Data Hunter, and n8n.

Fixes: corrects URL (must include /v1/), adds retry logic, timeout handling, and unified logging.

Usage:
    from shared.deepseek import DeepSeekClient

    client = DeepSeekClient()
    result = client.chat(prompt="What is the price of gold?", system="You are a trading analyst.")
    
    # Or use environment variable:
    # DEEPSEEK_API_KEY=sk-xxx
"""

import os
import time
from typing import Any, Dict, List, Optional

import httpx

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1/chat/completions"  # CRITICAL: /v1/ is required
DEFAULT_MODEL = "deepseek-chat"
DEFAULT_TIMEOUT = 30.0
MAX_RETRIES = 2
RETRY_BACKOFF = 2.0  # seconds, exponential


class DeepSeekError(Exception):
    """Base exception for DeepSeek API errors."""
    pass


class DeepSeekAuthError(DeepSeekError):
    """Authentication failed — API key missing or invalid."""
    pass


class DeepSeekTimeoutError(DeepSeekError):
    """Request timed out after all retries."""
    pass


class DeepSeekAPIError(DeepSeekError):
    """API returned a non-200 status code."""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"DeepSeek API error {status_code}: {message}")


class DeepSeekClient:
    """
    Unified DeepSeek API client for all agents.
    
    Configuration via environment:
        DEEPSEEK_API_KEY (required)
        DEEPSEEK_MODEL (optional, default: deepseek-chat)
        DEEPSEEK_TIMEOUT (optional, default: 30s)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.api_key = api_key or DEEPSEEK_API_KEY
        self.model = model or os.environ.get("DEEPSEEK_MODEL", DEFAULT_MODEL)
        self.timeout = timeout or float(os.environ.get("DEEPSEEK_TIMEOUT", str(DEFAULT_TIMEOUT)))

    @property
    def is_configured(self) -> bool:
        """Check if DeepSeek is properly configured."""
        return bool(self.api_key)

    def _build_messages(
        self,
        prompt: str,
        system: Optional[str] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ) -> List[Dict[str, str]]:
        """Build message list from prompt + optional system + history."""
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        if conversation_history:
            messages.extend(conversation_history)
        messages.append({"role": "user", "content": prompt})
        return messages

    def chat(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        json_mode: bool = False,
    ) -> Dict[str, Any]:
        """
        Send a chat completion request to DeepSeek.
        
        Args:
            prompt: User prompt text
            system: Optional system message (sets AI behavior)
            temperature: 0.0-1.0 (lower = more deterministic)
            max_tokens: Max tokens in response
            conversation_history: Previous messages for multi-turn
            json_mode: Force JSON output
        
        Returns:
            Dict with keys: response (str), model (str), usage (dict), finish_reason (str)
        
        Raises:
            DeepSeekAuthError: API key missing/invalid
            DeepSeekTimeoutError: Request timed out
            DeepSeekAPIError: API returned error
        """
        if not self.api_key:
            raise DeepSeekAuthError(
                "DeepSeek API key not configured. Set DEEPSEEK_API_KEY environment variable."
            )

        messages = self._build_messages(prompt, system, conversation_history)

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }

        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        last_error = None
        for attempt in range(MAX_RETRIES + 1):
            try:
                resp = httpx.post(
                    DEEPSEEK_BASE_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                    timeout=self.timeout,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    choice = data["choices"][0]
                    return {
                        "response": choice["message"]["content"].strip(),
                        "model": data.get("model", self.model),
                        "usage": data.get("usage", {}),
                        "finish_reason": choice.get("finish_reason", "stop"),
                    }

                if resp.status_code in (401, 403):
                    raise DeepSeekAuthError(
                        f"DeepSeek authentication failed (HTTP {resp.status_code}). Check DEEPSEEK_API_KEY."
                    )

                # Rate limit or server error — retryable
                if resp.status_code in (429, 500, 502, 503):
                    if attempt < MAX_RETRIES:
                        sleep_time = RETRY_BACKOFF ** (attempt + 1)
                        print(f"[deepseek] HTTP {resp.status_code} — retrying in {sleep_time:.1f}s (attempt {attempt + 1}/{MAX_RETRIES})")
                        time.sleep(sleep_time)
                        continue
                    # Fall through to error
                else:
                    # Non-retryable error
                    raise DeepSeekAPIError(resp.status_code, resp.text[:300])

                last_error = DeepSeekAPIError(resp.status_code, resp.text[:300])

            except httpx.TimeoutException:
                if attempt < MAX_RETRIES:
                    print(f"[deepseek] Timeout — retrying (attempt {attempt + 1}/{MAX_RETRIES})")
                    continue
                raise DeepSeekTimeoutError(
                    f"DeepSeek API timed out after {MAX_RETRIES + 1} attempts (timeout={self.timeout}s)"
                )
            except (DeepSeekAuthError, DeepSeekAPIError):
                raise
            except Exception as e:
                if attempt < MAX_RETRIES:
                    print(f"[deepseek] Error: {e} — retrying (attempt {attempt + 1}/{MAX_RETRIES})")
                    time.sleep(RETRY_BACKOFF ** (attempt + 1))
                    continue
                raise DeepSeekError(f"DeepSeek request failed: {str(e)}")

        if last_error:
            raise last_error
        raise DeepSeekError("DeepSeek request failed after all retries")

    def summarize(
        self,
        content: str,
        context: str = "You are a professional analyst. Summarize the following content.",
        language: str = "he",
        max_tokens: int = 500,
    ) -> str:
        """
        Quick summarization helper — simplified interface for agents.
        
        Args:
            content: Text to summarize
            context: System prompt describing the summarization task
            language: Output language (he/en)
            max_tokens: Max summary length
        
        Returns:
            Summary string (empty string on failure)
        """
        sys_msg = f"{context}\nRespond in {'Hebrew' if language == 'he' else 'English'}."
        try:
            result = self.chat(
                prompt=content,
                system=sys_msg,
                temperature=0.3,
                max_tokens=max_tokens,
            )
            return result["response"]
        except DeepSeekError as e:
            print(f"[deepseek] Summarization failed: {e}")
            return ""
        except Exception as e:
            print(f"[deepseek] Summarization error: {e}")
            return ""


# ── Singleton ────────────────────────────────────────

_client: Optional[DeepSeekClient] = None


def get_deepseek() -> DeepSeekClient:
    """Get or create the singleton DeepSeekClient."""
    global _client
    if _client is None:
        _client = DeepSeekClient()
    return _client