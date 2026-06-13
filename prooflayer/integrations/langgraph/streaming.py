"""Streaming output filtering for ProofLayer-protected LangGraph graphs."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, TYPE_CHECKING

from .exceptions import BlockedError

if TYPE_CHECKING:
    from .middleware import SecurityMiddleware


class StreamingFilter:
    """Inspect streamed LangGraph chunks and handle critical findings."""

    def __init__(self, middleware: "SecurityMiddleware") -> None:
        """Create a streaming filter bound to a middleware instance."""
        self.middleware = middleware

    def filter_chunk(
        self,
        chunk: Any,
        config: Optional[Dict[str, Any]] = None,
        stream_type: str = "stream",
    ) -> Any:
        """Inspect a streamed chunk and return the allowed replacement."""
        try:
            self.middleware.scan_output(chunk, config)
        except BlockedError as exc:
            if self.middleware.config.streaming_block_mode == "raise":
                raise
            replacement = self._replacement_chunk(chunk)
            self.middleware.record_event(
                {
                    "event_type": "stream_blocked",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "session_id": self.middleware.extract_session_id(config, chunk),
                    "stream_type": stream_type,
                    "reason": str(exc),
                    "replacement": replacement,
                }
            )
            return replacement
        return chunk

    def _replacement_chunk(self, chunk: Any) -> Any:
        token = self.middleware.config.blocked_token
        if isinstance(chunk, dict):
            return {"blocked": True, "content": token}
        return token
