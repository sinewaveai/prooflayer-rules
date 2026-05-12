"""
ProofLayer Transport Proxy
===========================

HTTP reverse proxy that intercepts MCP JSON-RPC tool calls
for security scanning. Designed for MCP servers that speak HTTP.

Usage:
    proxy = ProofLayerTransportProxy(listen_port=8080, backend_port=8081)
    proxy.start()  # blocking
    # or
    proxy.start_background()  # returns Thread
"""

import json
import logging
import threading
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Optional

import httpx

from ..detection.engine import DetectionEngine
from ..detection.detector_client import ExternalDetectorClient, apply_detector_result
from ..reporting.reporter import SecurityReporter
from ..response.actions import ResponseAction

logger = logging.getLogger(__name__)


class ProofLayerTransportProxy:
    """HTTP reverse proxy with MCP tool call security scanning."""

    def __init__(
        self,
        listen_port: int = 8080,
        backend_port: int = 8081,
        backend_host: str = "127.0.0.1",
        detection_engine: Optional[DetectionEngine] = None,
        reporter: Optional[SecurityReporter] = None,
        response_action: Optional[ResponseAction] = None,
        rules_dir: Optional[str] = None,
        report_dir: str = "./security-reports",
        action_on_threat: str = "block",
        kill_on_threat: bool = False,
        detector_client: Optional[ExternalDetectorClient] = None,
        detector_url: Optional[str] = None,
        detector_timeout_ms: int = 250,
    ):
        self.listen_port = listen_port
        self.backend_host = backend_host
        self.backend_port = backend_port
        self.kill_on_threat = kill_on_threat

        # Initialize components (use provided or create defaults)
        self.engine = detection_engine or DetectionEngine(rules_dir=rules_dir)
        self.reporter = reporter or SecurityReporter(report_dir=report_dir)
        self.response_action = response_action or ResponseAction(
            default_action=action_on_threat, reporter=self.reporter
        )
        self.detector_client = detector_client
        if self.detector_client is None and detector_url:
            self.detector_client = ExternalDetectorClient(
                base_url=detector_url,
                timeout_ms=detector_timeout_ms,
            )

        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._client = httpx.Client(
            base_url=f"http://{backend_host}:{backend_port}",
            timeout=30.0,
        )

    def start(self):
        """Start the proxy server (blocking)."""
        handler = self._make_handler()
        self._server = ThreadingHTTPServer(("0.0.0.0", self.listen_port), handler)
        logger.info(
            "ProofLayer proxy listening on :%d, forwarding to %s:%d",
            self.listen_port, self.backend_host, self.backend_port,
        )
        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            self.stop()

    def start_background(self) -> threading.Thread:
        """Start the proxy in a background thread. Returns the thread."""
        handler = self._make_handler()
        self._server = ThreadingHTTPServer(("0.0.0.0", self.listen_port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        logger.info(
            "ProofLayer proxy started in background on :%d -> %s:%d",
            self.listen_port, self.backend_host, self.backend_port,
        )
        return self._thread

    def stop(self):
        """Stop the proxy server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._client:
            self._client.close()
        logger.info("ProofLayer proxy stopped")

    def _make_handler(self):
        """Create the request handler class with access to proxy instance."""
        proxy = self

        class ProxyHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length) if content_length else b""

                # Try to parse as JSON-RPC
                try:
                    payload = json.loads(body) if body else None
                except (json.JSONDecodeError, UnicodeDecodeError):
                    payload = None

                # Handle batch JSON-RPC (array of requests)
                if isinstance(payload, list):
                    batch_responses = [None] * len(payload)
                    items_to_forward = []  # (index, item) pairs

                    for i, item in enumerate(payload):
                        blocked, response = proxy._check_tool_call(item)
                        if blocked:
                            batch_responses[i] = response
                        else:
                            items_to_forward.append((i, item))

                    # Forward non-blocked items individually to backend
                    for idx, item in items_to_forward:
                        try:
                            item_body = json.dumps(item).encode("utf-8")
                            backend_response = proxy._client.post(
                                self.path,
                                content=item_body,
                                headers={
                                    k: v for k, v in self.headers.items()
                                    if k.lower() not in ("host", "content-length")
                                },
                            )
                            try:
                                batch_responses[idx] = json.loads(backend_response.content)
                            except (json.JSONDecodeError, UnicodeDecodeError):
                                batch_responses[idx] = {
                                    "jsonrpc": "2.0",
                                    "error": {"code": -32000, "message": "Invalid backend response"},
                                    "id": item.get("id") if isinstance(item, dict) else None,
                                }
                        except httpx.ConnectError:
                            batch_responses[idx] = {
                                "jsonrpc": "2.0",
                                "error": {"code": -32000, "message": "Backend unavailable"},
                                "id": item.get("id") if isinstance(item, dict) else None,
                            }
                        except httpx.TimeoutException:
                            batch_responses[idx] = {
                                "jsonrpc": "2.0",
                                "error": {"code": -32000, "message": "Backend timeout"},
                                "id": item.get("id") if isinstance(item, dict) else None,
                            }

                    self._send_json(200, batch_responses)
                    return

                elif isinstance(payload, dict):
                    blocked, response = proxy._check_tool_call(payload)
                    if blocked:
                        self._send_json(200, response)
                        return

                # Forward the request to backend
                try:
                    backend_response = proxy._client.post(
                        self.path,
                        content=body,
                        headers={
                            k: v for k, v in self.headers.items()
                            if k.lower() not in ("host", "content-length")
                        },
                    )
                    self.send_response(backend_response.status_code)
                    for key, value in backend_response.headers.items():
                        if key.lower() not in ("transfer-encoding", "content-encoding", "content-length"):
                            self.send_header(key, value)
                    response_body = backend_response.content
                    self.send_header("Content-Length", str(len(response_body)))
                    self.end_headers()
                    self.wfile.write(response_body)
                except httpx.ConnectError:
                    self._send_json(502, {
                        "jsonrpc": "2.0",
                        "error": {"code": -32000, "message": "Backend unavailable"},
                        "id": payload.get("id") if isinstance(payload, dict) else None,
                    })
                except httpx.TimeoutException:
                    self._send_json(504, {
                        "jsonrpc": "2.0",
                        "error": {"code": -32000, "message": "Backend timeout"},
                        "id": payload.get("id") if isinstance(payload, dict) else None,
                    })

            def do_GET(self):
                """Forward GET requests transparently."""
                try:
                    backend_response = proxy._client.get(
                        self.path,
                        headers={
                            k: v for k, v in self.headers.items()
                            if k.lower() not in ("host",)
                        },
                    )
                    self.send_response(backend_response.status_code)
                    for key, value in backend_response.headers.items():
                        if key.lower() not in ("transfer-encoding", "content-encoding", "content-length"):
                            self.send_header(key, value)
                    response_body = backend_response.content
                    self.send_header("Content-Length", str(len(response_body)))
                    self.end_headers()
                    self.wfile.write(response_body)
                except httpx.ConnectError:
                    self.send_response(502)
                    self.end_headers()

            def _send_json(self, status_code, data):
                body = json.dumps(data).encode("utf-8")
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                """Route access logs through Python logging."""
                logger.debug("Proxy: %s", format % args)

        return ProxyHandler

    def _check_tool_call(self, payload: dict) -> tuple:
        """
        Check if a JSON-RPC payload is a tools/call and scan it.

        Returns:
            (blocked: bool, response: dict or None)
        """
        # Only intercept tools/call JSON-RPC method
        method = payload.get("method", "")
        if method != "tools/call":
            return False, None

        params = payload.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        request_id = payload.get("id")

        if not tool_name:
            return False, None

        # Run detection
        result = self.engine.scan(tool_name=tool_name, arguments=arguments)
        detector_result = None
        if self.detector_client:
            detector_result = self.detector_client.scan(
                tool_name=tool_name,
                arguments=arguments,
                metadata={"jsonrpc_id": request_id},
            )
        apply_detector_result(result, detector_result)

        if result.score >= self.engine.score_threshold["block"][0]:
            # THREAT - block
            threat_type = "unknown"
            if result.matched_rules:
                top_rule = max(result.matched_rules, key=lambda r: r.score)
                threat_type = top_rule.category

            self.reporter.generate_report(
                threat_type=threat_type,
                tool_name=tool_name,
                arguments=arguments,
                risk_score=result.score,
                matched_rules=result.matched_rules,
                action="BLOCK",
                scan_result=result,
            )

            logger.warning(
                "BLOCKED tool call via proxy: %s (score=%d, rules=%s)",
                tool_name, result.score,
                [r.id for r in result.matched_rules],
            )

            blocked_response = {
                "jsonrpc": "2.0",
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Tool call blocked by ProofLayer: {tool_name} "
                                    f"(risk score: {result.score})",
                        }
                    ],
                    "isError": True,
                },
                "id": request_id,
            }
            return True, blocked_response

        if result.score >= self.engine.score_threshold["warn"][0]:
            logger.warning(
                "SUSPICIOUS tool call via proxy: %s (score=%d)",
                tool_name, result.score,
            )

        return False, None
