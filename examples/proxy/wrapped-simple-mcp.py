#!/usr/bin/env python3
"""
ProofLayer Security Proxy for simple-mcp

Wraps a Go-based simple-mcp server with runtime threat detection.

Usage:
    python wrapped-simple-mcp.py --listen-port 8080 --backend-port 8081
"""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="ProofLayer Security Proxy for simple-mcp")
    parser.add_argument("--listen-port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--backend-port", type=int, default=8081, help="Port where simple-mcp is running (default: 8081)")
    parser.add_argument("--config", type=str, default=None, help="Path to prooflayer.yaml config file")
    parser.add_argument("--report-dir", type=str, default="./security-reports", help="Directory for threat reports")
    args = parser.parse_args()

    from prooflayer.runtime.transport import ProofLayerTransportProxy

    proxy = ProofLayerTransportProxy(
        listen_port=args.listen_port,
        backend_port=args.backend_port,
        report_dir=args.report_dir,
    )

    print(f"ProofLayer proxy listening on :{args.listen_port}")
    print(f"Forwarding to simple-mcp on :{args.backend_port}")
    print(f"Security reports: {args.report_dir}")
    print()
    print("Press Ctrl+C to stop")

    try:
        proxy.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        proxy.stop()


if __name__ == "__main__":
    main()
