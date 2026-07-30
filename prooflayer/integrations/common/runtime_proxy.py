"""Generic secured runtime proxy for ProofLayer integrations."""

from typing import Any


class SecuredRuntimeProxy:
    """Proxy object that delegates unknown attributes to a wrapped runtime."""

    def __init__(self, target: Any, adapter: Any) -> None:
        """Create a runtime proxy bound to an integration adapter."""
        self._target = target
        self._adapter = adapter

    @property
    def target(self) -> Any:
        """Return the wrapped runtime target."""
        return self._target

    @property
    def adapter(self) -> Any:
        """Return the adapter that owns the proxy."""
        return self._adapter

    def __getattr__(self, name: str) -> Any:
        """Delegate unknown attributes to the wrapped target."""
        return getattr(self._target, name)
