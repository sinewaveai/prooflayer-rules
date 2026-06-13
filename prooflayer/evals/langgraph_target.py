"""Adapters that expose LangGraph agents as adversarial eval targets."""

from typing import Any, Dict, Optional


class LangGraphEvalTarget:
    """Thin adapter around a LangGraph-compatible agent for eval runners."""

    def __init__(self, graph: Any, name: str = "langgraph-agent") -> None:
        """Initialize the target with a compiled or secured LangGraph object."""
        self.graph = graph
        self.name = name

    def invoke(self, prompt: str, config: Optional[Dict[str, Any]] = None) -> str:
        """Invoke the target graph with a prompt and return text output."""
        payload = {"input": prompt}
        kwargs: Dict[str, Any] = {}
        if config is not None:
            kwargs["config"] = config
        result = self.graph.invoke(payload, **kwargs)
        return self._extract_text(result)

    async def ainvoke(
        self,
        prompt: str,
        config: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Invoke the target graph asynchronously and return text output."""
        payload = {"input": prompt}
        kwargs: Dict[str, Any] = {}
        if config is not None:
            kwargs["config"] = config
        result = await self.graph.ainvoke(payload, **kwargs)
        return self._extract_text(result)

    def handle_chat_completions(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle an OpenAI-compatible chat completions request."""
        messages = request.get("messages", [])
        prompt = "\n".join(
            str(message.get("content", ""))
            for message in messages
            if isinstance(message, dict)
        )
        content = self.invoke(prompt)
        return {
            "object": "chat.completion",
            "model": request.get("model", self.name),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": content},
                    "finish_reason": "stop",
                }
            ],
        }

    def _extract_text(self, result: Any) -> str:
        """Extract a stable text response from common LangGraph result shapes."""
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            for key in ("output", "answer", "response", "content", "text"):
                if key in result:
                    return str(result[key])
            if "messages" in result and result["messages"]:
                last_message = result["messages"][-1]
                if isinstance(last_message, dict):
                    return str(last_message.get("content", ""))
                return str(getattr(last_message, "content", last_message))
        return str(result)
