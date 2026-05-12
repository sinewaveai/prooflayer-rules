# Benchmarks

This directory contains two benchmark suites:

- **`run_benchmarks.py`** — detection-quality benchmark. Runs OWASP LLM01 prompt-injection fixtures and the local malicious / benign fixtures through the engine and reports detection rate and false-positive rate.
- **`latency.py`** — per-scan latency benchmark. Runs a 40/30/30 mix of benign / suspicious / attack inputs through the detection engine and reports p50 / p95 / p99 latency.

## Run

```bash
# Detection quality
python3 benchmarks/run_benchmarks.py

# Latency
python3 benchmarks/latency.py            # 10k scans, text output
python3 benchmarks/latency.py --json     # JSON output
python3 benchmarks/latency.py --n 50000  # larger sample
```

## Results — v0.1.0 release tag

Captured on **2026-05-12** against the v0.1.0 release tag.

**Hardware:** Apple M4 Max, 64 GB RAM, macOS Darwin 24.6.0, Python 3.9.6.

### Detection quality (`run_benchmarks.py`)

| Suite                                | Score      |
| ------------------------------------ | ---------- |
| OWASP LLM01 Detection Rate           | 15/15 (100%) |
| Malicious Fixture Detection Rate     | 31/31 (100%) |
| False Positive Rate (bench fixtures) | 0/20 (0%)    |
| False Positive Rate (fixt fixtures)  | 0/54 (0%)    |
| Total benchmark wall time            | ~546 ms      |

### Latency (`benchmarks/latency.py --n 10000`)

10,000 scans over a 40% benign / 30% suspicious / 30% attack input mix, seed=42, 200-scan warmup.

| Metric          | Value      |
| --------------- | ---------- |
| p50 latency     | 1.99 ms    |
| p95 latency     | 5.74 ms    |
| p99 latency     | 6.23 ms    |
| Mean latency    | 2.26 ms    |
| Max latency     | 8.79 ms    |
| Throughput      | ~442 scans/s |
| Wall time       | 22.6 s     |

## Notes

- The hot path is synchronous regex + heuristic matching. For latency-sensitive deployments (voice agents, sub-100 ms paths) the rules layer is the right choice.
- The commercial detector tier (`prooflayer-detector`) is async and recommended for non-hot-path analysis; runtime degrades to rules-only on detector failure.
- Numbers are workstation-class. Production p99 will vary with rule-set size, payload size, and CPU contention. Re-run on your target hardware before publishing claims.
