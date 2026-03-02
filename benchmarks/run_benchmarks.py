#!/usr/bin/env python3
"""
ProofLayer Benchmark Runner
============================

Runs all benchmark suites against the detection engine and prints results.

Usage:
    python benchmarks/run_benchmarks.py
"""

import json
import sys
import time
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from prooflayer.detection.engine import DetectionEngine

BENCHMARKS_DIR = Path(__file__).parent


def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def run_owasp_llm01(engine: DetectionEngine) -> dict:
    """Run OWASP LLM01 Prompt Injection benchmark."""
    data = load_json(BENCHMARKS_DIR / "owasp-llm-top10" / "LLM01_prompt_injection.json")
    payloads = data["payloads"]

    results = []
    detected = 0
    total = len(payloads)

    print("\n" + "=" * 70)
    print("OWASP LLM01: Prompt Injection Benchmark")
    print("=" * 70)
    print(f"{'ID':<12} {'Technique':<25} {'Score':>6} {'Expected':>9} {'Result':>8}")
    print("-" * 70)

    for payload in payloads:
        result = engine.scan(
            tool_name=payload["tool_name"],
            arguments=payload["arguments"],
        )
        score, matched = result
        expected = payload["expected_min_score"]
        passed = score >= expected

        if passed:
            detected += 1

        status = "PASS" if passed else "FAIL"
        print(
            f"{payload['id']:<12} {payload['technique']:<25} "
            f"{score:>6} {'>=' + str(expected):>9} {status:>8}"
        )

        results.append({
            "id": payload["id"],
            "technique": payload["technique"],
            "score": score,
            "expected_min": expected,
            "passed": passed,
            "matched_rules": len(matched),
        })

    rate = (detected / total * 100) if total > 0 else 0
    print("-" * 70)
    print(f"Detection Rate: {detected}/{total} ({rate:.1f}%)")
    print()

    return {
        "benchmark": "OWASP LLM01",
        "total": total,
        "detected": detected,
        "rate": rate,
        "results": results,
    }


def run_false_positives(engine: DetectionEngine) -> dict:
    """Run False Positive benchmark."""
    data = load_json(BENCHMARKS_DIR / "false-positives" / "benign_cases.json")
    cases = data["cases"]

    results = []
    false_positives = 0
    total = len(cases)

    print("\n" + "=" * 70)
    print("False Positive Benchmark")
    print("=" * 70)
    print(f"{'ID':<10} {'Domain':<18} {'Tool':<22} {'Score':>6} {'Max':>5} {'Result':>8}")
    print("-" * 70)

    for case in cases:
        result = engine.scan(
            tool_name=case["tool_name"],
            arguments=case["arguments"],
        )
        score, _ = result
        max_score = case["max_expected_score"]
        passed = score <= max_score

        if not passed:
            false_positives += 1

        status = "PASS" if passed else "FP"
        print(
            f"{case['id']:<10} {case['domain']:<18} {case['tool_name']:<22} "
            f"{score:>6} {'<=' + str(max_score):>5} {status:>8}"
        )

        results.append({
            "id": case["id"],
            "domain": case["domain"],
            "tool_name": case["tool_name"],
            "score": score,
            "max_expected": max_score,
            "passed": passed,
        })

    fp_rate = (false_positives / total * 100) if total > 0 else 0
    print("-" * 70)
    print(f"False Positives: {false_positives}/{total} ({fp_rate:.1f}%)")
    print(f"Accuracy: {total - false_positives}/{total} ({100 - fp_rate:.1f}%)")
    print()

    return {
        "benchmark": "False Positives",
        "total": total,
        "false_positives": false_positives,
        "fp_rate": fp_rate,
        "results": results,
    }


def run_fixture_benign(engine: DetectionEngine) -> dict:
    """Run benign fixture test cases from tests/fixtures/."""
    fixtures_path = project_root / "tests" / "fixtures" / "benign_tool_calls.json"
    cases = load_json(fixtures_path)

    results = []
    false_positives = 0
    total = len(cases)

    print("\n" + "=" * 70)
    print("Benign Tool Call Fixtures")
    print("=" * 70)
    print(f"{'#':<4} {'Tool':<28} {'Score':>6} {'Max':>5} {'Result':>8}")
    print("-" * 70)

    for i, case in enumerate(cases, 1):
        result = engine.scan(
            tool_name=case["tool_name"],
            arguments=case["arguments"],
        )
        score, _ = result
        max_score = case["max_expected_score"]
        passed = score < max_score

        if not passed:
            false_positives += 1

        status = "PASS" if passed else "FP"
        print(f"{i:<4} {case['tool_name']:<28} {score:>6} {'<' + str(max_score):>5} {status:>8}")

        results.append({
            "tool_name": case["tool_name"],
            "score": score,
            "max_expected": max_score,
            "passed": passed,
        })

    fp_rate = (false_positives / total * 100) if total > 0 else 0
    print("-" * 70)
    print(f"False Positives: {false_positives}/{total} ({fp_rate:.1f}%)")
    print()

    return {
        "benchmark": "Benign Fixtures",
        "total": total,
        "false_positives": false_positives,
        "fp_rate": fp_rate,
        "results": results,
    }


def run_fixture_malicious(engine: DetectionEngine) -> dict:
    """Run malicious fixture test cases from tests/fixtures/."""
    fixtures_path = project_root / "tests" / "fixtures" / "malicious_payloads.json"
    cases = load_json(fixtures_path)

    results = []
    detected = 0
    total = len(cases)

    print("\n" + "=" * 70)
    print("Malicious Payload Fixtures")
    print("=" * 70)
    print(f"{'#':<4} {'Tool':<22} {'Category':<22} {'Score':>6} {'Min':>5} {'Result':>8}")
    print("-" * 70)

    for i, case in enumerate(cases, 1):
        result = engine.scan(
            tool_name=case["tool_name"],
            arguments=case["arguments"],
        )
        score, _ = result
        min_score = case["min_expected_score"]
        passed = score >= min_score

        if passed:
            detected += 1

        status = "PASS" if passed else "MISS"
        print(
            f"{i:<4} {case['tool_name']:<22} {case['category']:<22} "
            f"{score:>6} {'>=' + str(min_score):>5} {status:>8}"
        )

        results.append({
            "tool_name": case["tool_name"],
            "category": case["category"],
            "score": score,
            "min_expected": min_score,
            "passed": passed,
        })

    rate = (detected / total * 100) if total > 0 else 0
    print("-" * 70)
    print(f"Detection Rate: {detected}/{total} ({rate:.1f}%)")
    print()

    return {
        "benchmark": "Malicious Fixtures",
        "total": total,
        "detected": detected,
        "rate": rate,
        "results": results,
    }


def main():
    print("ProofLayer Benchmark Suite")
    print(f"{'=' * 70}")

    # Initialize engine
    print("Initializing detection engine...")
    start = time.perf_counter()
    engine = DetectionEngine()
    init_time = (time.perf_counter() - start) * 1000
    print(f"Engine ready: {len(engine.rules)} rules loaded in {init_time:.1f}ms")

    # Run all benchmarks
    all_results = {}
    total_start = time.perf_counter()

    all_results["owasp_llm01"] = run_owasp_llm01(engine)
    all_results["false_positives"] = run_false_positives(engine)
    all_results["benign_fixtures"] = run_fixture_benign(engine)
    all_results["malicious_fixtures"] = run_fixture_malicious(engine)

    total_time = (time.perf_counter() - total_start) * 1000

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    owasp = all_results["owasp_llm01"]
    fp = all_results["false_positives"]
    benign = all_results["benign_fixtures"]
    malicious = all_results["malicious_fixtures"]

    print(f"  OWASP LLM01 Detection Rate:  {owasp['detected']}/{owasp['total']} ({owasp['rate']:.1f}%)")
    print(f"  Malicious Fixture Detection: {malicious['detected']}/{malicious['total']} ({malicious['rate']:.1f}%)")
    print(f"  False Positive Rate (bench): {fp['false_positives']}/{fp['total']} ({fp['fp_rate']:.1f}%)")
    print(f"  False Positive Rate (fixt):  {benign['false_positives']}/{benign['total']} ({benign['fp_rate']:.1f}%)")
    print(f"  Total Benchmark Time:        {total_time:.1f}ms")
    print()

    # Determine exit code
    all_passed = (
        owasp["rate"] == 100.0
        and malicious["rate"] == 100.0
        and fp["fp_rate"] == 0.0
        and benign["fp_rate"] == 0.0
    )

    if all_passed:
        print("ALL BENCHMARKS PASSED")
    else:
        print("SOME BENCHMARKS FAILED - review results above")

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
