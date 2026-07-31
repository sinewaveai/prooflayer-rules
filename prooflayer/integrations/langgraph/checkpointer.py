"""LangGraph checkpointer wrapper that records audit checkpoints."""

from datetime import datetime, timezone
from typing import Any, AsyncIterator, Dict, Iterator, Optional, Sequence

from langgraph.checkpoint.base import (
    BaseCheckpointSaver,
    ChannelVersions,
    Checkpoint,
    CheckpointMetadata,
    CheckpointTuple,
)
from langgraph.checkpoint.memory import InMemorySaver
from langchain_core.runnables import RunnableConfig


class AuditCheckpointer(BaseCheckpointSaver):
    """Delegate checkpoint storage while capturing auditable state events."""

    def __init__(self, delegate: Optional[BaseCheckpointSaver] = None) -> None:
        """Create an audit checkpointer backed by another saver."""
        super().__init__()
        self.delegate = delegate or InMemorySaver()
        self.audit_log: list[Dict[str, Any]] = []

    def get_tuple(self, config: RunnableConfig) -> Optional[CheckpointTuple]:
        """Return the checkpoint tuple from the delegated saver."""
        return self.delegate.get_tuple(config)

    def put(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        """Persist a checkpoint and record audit metadata."""
        result = self.delegate.put(config, checkpoint, metadata, new_versions)
        self._record_checkpoint("checkpoint_put", config, checkpoint, metadata)
        return result

    def put_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        """Persist intermediate writes and record audit metadata."""
        self.delegate.put_writes(config, writes, task_id, task_path)
        self._record_checkpoint(
            "checkpoint_writes",
            config,
            {"writes": list(writes), "task_id": task_id, "task_path": task_path},
            {},
        )

    def list(
        self,
        config: Optional[RunnableConfig],
        *,
        filter: Optional[dict[str, Any]] = None,
        before: Optional[RunnableConfig] = None,
        limit: Optional[int] = None,
    ) -> Iterator[CheckpointTuple]:
        """List checkpoints from the delegated saver."""
        return self.delegate.list(config, filter=filter, before=before, limit=limit)

    async def aget_tuple(self, config: RunnableConfig) -> Optional[CheckpointTuple]:
        """Return the checkpoint tuple from the delegated async saver."""
        return await self.delegate.aget_tuple(config)

    async def aput(
        self,
        config: RunnableConfig,
        checkpoint: Checkpoint,
        metadata: CheckpointMetadata,
        new_versions: ChannelVersions,
    ) -> RunnableConfig:
        """Persist an async checkpoint and record audit metadata."""
        result = await self.delegate.aput(config, checkpoint, metadata, new_versions)
        self._record_checkpoint("checkpoint_put", config, checkpoint, metadata)
        return result

    async def aput_writes(
        self,
        config: RunnableConfig,
        writes: Sequence[tuple[str, Any]],
        task_id: str,
        task_path: str = "",
    ) -> None:
        """Persist async intermediate writes and record audit metadata."""
        await self.delegate.aput_writes(config, writes, task_id, task_path)
        self._record_checkpoint(
            "checkpoint_writes",
            config,
            {"writes": list(writes), "task_id": task_id, "task_path": task_path},
            {},
        )

    async def alist(
        self,
        config: Optional[RunnableConfig],
        *,
        filter: Optional[dict[str, Any]] = None,
        before: Optional[RunnableConfig] = None,
        limit: Optional[int] = None,
    ) -> AsyncIterator[CheckpointTuple]:
        """List checkpoints from the delegated async saver."""
        async for checkpoint in self.delegate.alist(
            config,
            filter=filter,
            before=before,
            limit=limit,
        ):
            yield checkpoint

    def _record_checkpoint(
        self,
        event_type: str,
        config: RunnableConfig,
        checkpoint: Any,
        metadata: Any,
    ) -> None:
        configurable = config.get("configurable", {}) if config else {}
        self.audit_log.append(
            {
                "event_type": event_type,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "thread_id": configurable.get("thread_id"),
                "checkpoint_id": (
                    checkpoint.get("id") if isinstance(checkpoint, dict) else None
                ),
                "metadata": metadata,
            }
        )
