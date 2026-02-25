#!/usr/bin/env python3
"""
Test Runner for ProofLayer Runtime Security
============================================

Runs all test suites and generates a summary report.
"""

import sys
import os
import unittest
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def run_all_tests():
    """Discover and run all tests."""
    print("\n" + "="*80)
    print("ProofLayer Runtime Security - Test Suite")
    print("="*80 + "\n")

    # Discover all tests in the tests directory
    loader = unittest.TestLoader()
    start_dir = os.path.dirname(__file__)
    suite = loader.discover(start_dir, pattern="test_*.py")

    # Run tests with detailed output
    runner = unittest.TextTestRunner(verbosity=2)

    start_time = time.time()
    result = runner.run(suite)
    elapsed_time = time.time() - start_time

    # Print summary
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    print(f"Tests Run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print(f"Time: {elapsed_time:.2f} seconds")
    print("="*80 + "\n")

    if result.wasSuccessful():
        print("✅ ALL TESTS PASSED")
        return 0
    else:
        print("❌ SOME TESTS FAILED")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)
