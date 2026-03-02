"""
Prometheus Metrics
==================

Lightweight metrics collection and exposition for ProofLayer.
Uses only stdlib (no prometheus_client dependency).

Exposes metrics at /metrics in Prometheus text exposition format via http.server.

Usage:
    from prooflayer.metrics import metrics, start_metrics_server

    # Record a scan
    metrics.record_scan(action="block", duration=0.003, risk_score=85,
                        matched_rules=[("cmd-inject-curl", "command_injection")])

    # Start HTTP endpoint
    start_metrics_server(port=9090)
"""

import threading
import time
import math
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Tuple, Optional


class _Counter:
    """Thread-safe counter with optional labels."""

    def __init__(self):
        self._lock = threading.Lock()
        self._values: Dict[tuple, float] = {}

    def inc(self, labels: Optional[Dict[str, str]] = None, value: float = 1.0):
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._values[key] = self._values.get(key, 0.0) + value

    def collect(self) -> Dict[tuple, float]:
        with self._lock:
            return dict(self._values)


class _Gauge:
    """Thread-safe gauge."""

    def __init__(self):
        self._lock = threading.Lock()
        self._values: Dict[tuple, float] = {}

    def set(self, value: float, labels: Optional[Dict[str, str]] = None):
        key = tuple(sorted((labels or {}).items()))
        with self._lock:
            self._values[key] = value

    def collect(self) -> Dict[tuple, float]:
        with self._lock:
            return dict(self._values)


class _HistogramLike:
    """Tracks min, max, sum, count, and sorted observations for percentile computation."""

    def __init__(self):
        self._lock = threading.Lock()
        self._observations: List[float] = []
        self._sum: float = 0.0
        self._count: int = 0
        self._min: float = float("inf")
        self._max: float = float("-inf")

    def observe(self, value: float):
        with self._lock:
            self._observations.append(value)
            self._sum += value
            self._count += 1
            if value < self._min:
                self._min = value
            if value > self._max:
                self._max = value

    def collect(self) -> Dict[str, float]:
        with self._lock:
            if self._count == 0:
                return {
                    "count": 0, "sum": 0, "min": 0, "max": 0,
                    "avg": 0, "p50": 0, "p95": 0, "p99": 0,
                }
            sorted_obs = sorted(self._observations)
            return {
                "count": self._count,
                "sum": self._sum,
                "min": self._min,
                "max": self._max,
                "avg": self._sum / self._count,
                "p50": _percentile(sorted_obs, 0.50),
                "p95": _percentile(sorted_obs, 0.95),
                "p99": _percentile(sorted_obs, 0.99),
            }


def _percentile(sorted_data: List[float], pct: float) -> float:
    """Compute percentile from sorted list using nearest-rank method."""
    if not sorted_data:
        return 0.0
    idx = int(math.ceil(pct * len(sorted_data))) - 1
    return sorted_data[max(0, idx)]


class MetricsCollector:
    """Central metrics collector for ProofLayer."""

    def __init__(self):
        self.scans_total = _Counter()
        self.scan_duration = _HistogramLike()
        self.rules_matched_total = _Counter()
        self.risk_score_last = _Gauge()
        self.risk_score_avg = _Gauge()
        self.active_rules = _Gauge()

        self._lock = threading.Lock()
        self._score_sum: float = 0.0
        self._score_count: int = 0
        self.enabled: bool = False

    def record_scan(
        self,
        action: str,
        duration: float,
        risk_score: int,
        matched_rules: Optional[List[Tuple[str, str]]] = None,
    ):
        """
        Record a completed scan.

        Args:
            action: The action taken (allow, warn, block, kill)
            duration: Scan duration in seconds
            risk_score: Computed risk score (0-100)
            matched_rules: List of (rule_id, category) tuples
        """
        if not self.enabled:
            return

        self.scans_total.inc(labels={"action": action.lower()})
        self.scan_duration.observe(duration)

        self.risk_score_last.set(float(risk_score))
        with self._lock:
            self._score_sum += risk_score
            self._score_count += 1
            self.risk_score_avg.set(self._score_sum / self._score_count)

        for rule_id, category in (matched_rules or []):
            self.rules_matched_total.inc(
                labels={"rule_id": rule_id, "category": category}
            )

    def set_active_rules(self, count: int):
        """Set the number of currently active rules."""
        if not self.enabled:
            return
        self.active_rules.set(float(count))

    def render_prometheus(self) -> str:
        """Render all metrics in Prometheus text exposition format."""
        lines: List[str] = []

        # prooflayer_scans_total
        lines.append("# HELP prooflayer_scans_total Total number of scans performed.")
        lines.append("# TYPE prooflayer_scans_total counter")
        for labels, value in self.scans_total.collect().items():
            label_str = _labels_to_str(labels)
            lines.append(f"prooflayer_scans_total{{{label_str}}} {value}")

        # prooflayer_scan_duration_seconds
        dur = self.scan_duration.collect()
        lines.append("# HELP prooflayer_scan_duration_seconds Scan duration statistics.")
        lines.append("# TYPE prooflayer_scan_duration_seconds summary")
        lines.append(f'prooflayer_scan_duration_seconds{{quantile="0.5"}} {dur["p50"]}')
        lines.append(f'prooflayer_scan_duration_seconds{{quantile="0.95"}} {dur["p95"]}')
        lines.append(f'prooflayer_scan_duration_seconds{{quantile="0.99"}} {dur["p99"]}')
        lines.append(f'prooflayer_scan_duration_seconds_count {dur["count"]}')
        lines.append(f'prooflayer_scan_duration_seconds_sum {dur["sum"]}')
        lines.append(f'prooflayer_scan_duration_seconds_min {dur["min"]}')
        lines.append(f'prooflayer_scan_duration_seconds_max {dur["max"]}')
        lines.append(f'prooflayer_scan_duration_seconds_avg {dur["avg"]}')

        # prooflayer_rules_matched_total
        lines.append("# HELP prooflayer_rules_matched_total Total rules matched.")
        lines.append("# TYPE prooflayer_rules_matched_total counter")
        for labels, value in self.rules_matched_total.collect().items():
            label_str = _labels_to_str(labels)
            lines.append(f"prooflayer_rules_matched_total{{{label_str}}} {value}")

        # prooflayer_risk_score
        lines.append("# HELP prooflayer_risk_score Risk score gauge.")
        lines.append("# TYPE prooflayer_risk_score gauge")
        for labels, value in self.risk_score_last.collect().items():
            lines.append(f'prooflayer_risk_score{{stat="last"}} {value}')
        for labels, value in self.risk_score_avg.collect().items():
            lines.append(f'prooflayer_risk_score{{stat="avg"}} {value}')

        # prooflayer_active_rules
        lines.append("# HELP prooflayer_active_rules Number of active detection rules.")
        lines.append("# TYPE prooflayer_active_rules gauge")
        for labels, value in self.active_rules.collect().items():
            lines.append(f"prooflayer_active_rules {value}")

        lines.append("")  # trailing newline
        return "\n".join(lines)


def _labels_to_str(labels: tuple) -> str:
    """Convert label tuple to Prometheus label string."""
    parts = [f'{k}="{v}"' for k, v in labels]
    return ",".join(parts)


# Singleton collector
metrics = MetricsCollector()


class _MetricsHandler(BaseHTTPRequestHandler):
    """HTTP handler that serves Prometheus metrics."""

    def do_GET(self):
        if self.path == "/metrics":
            body = metrics.render_prometheus().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress default access log noise
        pass


_server_instance: Optional[HTTPServer] = None


def start_metrics_server(port: int = 9090) -> HTTPServer:
    """
    Start the Prometheus metrics HTTP server on a background thread.

    Args:
        port: TCP port to listen on (default 9090)

    Returns:
        HTTPServer instance (call .shutdown() to stop)
    """
    global _server_instance
    if _server_instance is not None:
        return _server_instance

    server = HTTPServer(("0.0.0.0", port), _MetricsHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    _server_instance = server
    return server
