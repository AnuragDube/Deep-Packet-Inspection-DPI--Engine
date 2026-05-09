# Main entry point for the DPI Engine

import argparse
import sys
from collections import Counter
from scapy.all import rdpcap
from src.packet_parser import parse
from src.sni_extractor import extract_sni, extract_http_host
from src.app_classifier import classify
from src.flow_tracker import FlowTracker
from src.rule_manager import RuleEngine


def run(args):
    """Run the DPI engine on a PCAP file with optional blocking rules."""
    # Initialize rule engine and add blocking rules
    rules = RuleEngine()

    for ip in args.block_ip:
        rules.add_blocked_ip(ip)

    for app in args.block_app:
        rules.add_blocked_app(app)

    for domain in args.block_domain:
        rules.add_blocked_domain(domain)

    # Initialize flow tracker
    tracker = FlowTracker()

    # Read PCAP file
    try:
        packets = rdpcap(args.input)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        sys.exit(1)

    total_packets = len(packets)
    print(f"Processing {total_packets} packets from {args.input}\n")

    forwarded = 0
    dropped = 0

    # Process each packet
    for pkt in packets:
        raw_bytes = bytes(pkt)
        parsed = parse(raw_bytes)

        if parsed is None:
            continue

        # Get or create flow
        flow = tracker.get_or_create(
            parsed.src_ip, parsed.dst_ip,
            parsed.src_port, parsed.dst_port,
            parsed.protocol
        )

        # Skip if flow is already blocked
        if flow.blocked:
            dropped += 1
            continue

        # Extract domain information
        sni = ""
        if parsed.dst_port == 443 and parsed.payload:
            sni = extract_sni(parsed.payload) or ""
        elif parsed.dst_port == 80 and parsed.payload:
            sni = extract_http_host(parsed.payload) or ""

        # Classify application
        app = classify(sni, parsed.dst_port, parsed.protocol)

        # Update flow statistics
        payload_len = len(parsed.payload)
        tracker.update(flow, payload_len, sni, app)

        # Check blocking rules
        if rules.is_blocked(parsed.src_ip, app, sni):
            flow.blocked = True
            dropped += 1
            continue

        forwarded += 1

    # Generate report
    print("\n" + "="*50)
    print("DPI ENGINE REPORT")
    print("="*50)
    print(f"Total packets: {total_packets}")
    print(f"Forwarded: {forwarded}")
    print(f"Dropped: {dropped}")
    print()

    # App breakdown
    all_flows = list(tracker.all_flows())
    app_counter = Counter(flow.app for flow in all_flows if flow.app != "Unknown")

    if app_counter:
        print("Application Breakdown:")
        for app, count in app_counter.most_common():
            print(f"  {app}: {count} flows")
        print()

    # Domain detection report
    domains_found = {}
    for flow in all_flows:
        if flow.sni and flow.app != "Unknown":
            domains_found[flow.sni] = flow.app

    if domains_found:
        print("Detected Domains:")
        for domain, app in sorted(domains_found.items()):
            print(f"  {domain} -> {app}")
    else:
        print("No domains detected")

    print("="*50)


def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description="Deep Packet Inspection Engine")
    parser.add_argument("input", help="Input PCAP file")
    parser.add_argument("output", nargs="?", help="Output PCAP file (optional)")
    parser.add_argument("--block-ip", action="append", default=[], help="Block IP address")
    parser.add_argument("--block-app", action="append", default=[], help="Block application")
    parser.add_argument("--block-domain", action="append", default=[], help="Block domain")

    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
