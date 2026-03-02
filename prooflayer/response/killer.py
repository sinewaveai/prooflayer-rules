"""
Server Killer
=============

Emergency MCP server termination for critical threats.
"""

import os
import sys
import signal
import logging
import time
from typing import Dict, Any

logger = logging.getLogger(__name__)


class ServerKiller:
    """Handles emergency termination of MCP server processes."""

    def kill(self, context: Dict[str, Any]) -> None:
        """
        Terminate the MCP server process.

        Writes an emergency log, sends SIGTERM, then SIGKILL if needed.

        Args:
            context: Context information (tool_name, risk_score, arguments, etc.)
        """
        logger.critical("=" * 80)
        logger.critical("PROOFLAYER RUNTIME SECURITY: CRITICAL THREAT DETECTED")
        logger.critical("Tool: %s", context.get("tool_name"))
        logger.critical("Risk Score: %s", context.get("risk_score"))
        logger.critical("Action: MCP SERVER TERMINATED")
        logger.critical("=" * 80)

        # Write emergency log with restricted permissions
        emergency_path = "/tmp/prooflayer-emergency.log"
        try:
            fd = os.open(
                emergency_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                0o600,
            )
            with os.fdopen(fd, "a") as f:
                f.write(f"\n{'=' * 80}\n")
                f.write(f"TIMESTAMP: {context.get('timestamp', 'N/A')}\n")
                f.write(f"TOOL: {context.get('tool_name')}\n")
                f.write(f"RISK SCORE: {context.get('risk_score')}\n")
                f.write(f"ARGUMENTS: {context.get('arguments')}\n")
                f.write(f"{'=' * 80}\n")
            os.chmod(emergency_path, 0o600)
        except Exception as e:
            logger.error("Failed to write emergency log: %s", e)

        # Kill the process
        pid = os.getpid()
        logger.critical("Sending SIGTERM to process %d", pid)

        sys.stdout.flush()
        sys.stderr.flush()

        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except (PermissionError, ProcessLookupError):
            os.kill(pid, signal.SIGTERM)

        # If still running after 1 second, force kill
        time.sleep(1)
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (PermissionError, ProcessLookupError):
            os.kill(pid, signal.SIGKILL)
