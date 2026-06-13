#!/usr/bin/env python3
"""ProofLayer LangGraph hot-path latency benchmark."""

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Dict, TypedDict

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from langgraph.graph import END, StateGraph

from prooflayer.integrations.langgraph import SecurityConfig, SecurityMiddleware


class BenchState(TypedDict):
    """State for the benchmark graph."""

    input: str
    answer: str


def answer(state: BenchState) -> Dict[str, str]:
    """Return a deterministic answer for a representative node."""
    return {"answer": f"ok:{state['input']}"}


def percentile(samples: list[float], p: float) -> float:
    """Nearest-rank percentile, p in [0, 100]."""
    if not samples:
        return 0.0
    sorted_samples = sorted(samples)
    index = max(
        0,
        min(len(sorted_samples) - 1, int(round(p / 100 * (len(sorted_samples) - 1)))),
    )
    return sorted_samples[index]


def build_secured_graph():
    """Build a representative secured LangGraph."""
    graph = StateGraph(BenchState)
    graph.add_node("answer", answer)
    graph.set_entry_point("answer")
    graph.add_edge("answer", END)

    middleware = SecurityMiddleware(
        SecurityConfig(
            prompt_injection="block",
            jailbreak="block",
            tool_abuse="block",
            exfil="block",
            scope_drift="warn",
            state_manipulation="block",
            multi_turn="warn",
            emit_to=["stdout"],
        )
    )
    return middleware.wrap(graph.compile())


def main() -> int:
    """Run the LangGraph hot-path benchmark."""
    parser = argparse.ArgumentParser(
        description="ProofLayer LangGraph latency benchmark"
    )
    parser.add_argument("--n", type=int, default=200, help="number of invokes")
    parser.add_argument("--json", action="store_true", help="emit JSON, not text")
    args = parser.parse_args()

    graph = build_secured_graph()
    payload = {"input": "summarize the approved runbook", "answer": ""}
    config = {"configurable": {"thread_id": "bench-thread"}}

    for _ in range(min(50, args.n)):
        graph.invoke(payload, config=config)

    latencies_ms: list[float] = []
    start = time.perf_counter()
    for _ in range(args.n):
        t0 = time.perf_counter()
        graph.invoke(payload, config=config)
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)
    wall_s = time.perf_counter() - start

    summary = {
        "samples": len(latencies_ms),
        "wall_seconds": round(wall_s, 3),
        "throughput_per_second": round(len(latencies_ms) / wall_s, 1),
        "p50_ms": round(percentile(latencies_ms, 50), 4),
        "p95_ms": round(percentile(latencies_ms, 95), 4),
        "p99_ms": round(percentile(latencies_ms, 99), 4),
        "mean_ms": round(statistics.fmean(latencies_ms), 4),
        "max_ms": round(max(latencies_ms), 4),
    }

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("=" * 60)
        print(" ProofLayer LangGraph Hot-Path Benchmark")
        print("=" * 60)
        print(f"  samples         : {summary['samples']}")
        print(f"  wall time       : {summary['wall_seconds']} s")
        print(f"  throughput      : {summary['throughput_per_second']} invokes/s")
        print(f"  p50 latency     : {summary['p50_ms']} ms")
        print(f"  p95 latency     : {summary['p95_ms']} ms")
        print(f"  p99 latency     : {summary['p99_ms']} ms")
        print(f"  mean latency    : {summary['mean_ms']} ms")
        print(f"  max latency     : {summary['max_ms']} ms")
        print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
