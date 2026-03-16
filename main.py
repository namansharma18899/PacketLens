#!/usr/bin/env python3
"""CLI for DPI engine: read PCAP, apply rules, write filtered PCAP and report."""

import argparse
import sys

from rule_manager import RuleManager
from dpi_engine import run_dpi


def main() -> int:
    parser = argparse.ArgumentParser(
        description="DPI Engine - Deep Packet Inspection (filter PCAP by rules)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s capture.pcap filtered.pcap
  %(prog)s capture.pcap out.pcap --block-app YouTube --block-ip 192.168.1.50
  %(prog)s capture.pcap out.pcap --block-domain facebook
        """,
    )
    parser.add_argument("input_pcap", help="Input PCAP file")
    parser.add_argument("output_pcap", help="Output PCAP file (filtered)")
    parser.add_argument("--block-ip", dest="block_ips", action="append", default=[], metavar="IP", help="Block traffic from source IP")
    parser.add_argument("--block-app", dest="block_apps", action="append", default=[], metavar="APP", help="Block app (e.g. YouTube, Facebook)")
    parser.add_argument("--block-domain", dest="block_domains", action="append", default=[], metavar="DOM", help="Block domain (substring match)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Less output")
    args = parser.parse_args()

    rules = RuleManager()
    for ip in args.block_ips:
        rules.block_ip(ip)
    for app in args.block_apps:
        rules.block_app(app)
    for dom in args.block_domains:
        rules.block_domain(dom)

    if not args.quiet:
        print()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║                    DPI ENGINE v1.0 (Python)                   ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()

    ok = run_dpi(args.input_pcap, args.output_pcap, rules, verbose=not args.quiet)
    if not ok:
        return 1
    if not args.quiet:
        print("\nOutput written to:", args.output_pcap)
    return 0


if __name__ == "__main__":
    sys.exit(main())
