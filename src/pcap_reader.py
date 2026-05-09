import sys
from scapy.all import rdpcap
from src.packet_parser import parse
from src.sni_extractor import extract_sni, extract_http_host


def read_pcap(filepath: str) -> None:
    """
    Read and analyze a PCAP file, parsing packets and extracting domain information.
    
    For each packet, extracts IP/port information and attempts to identify
    domains via SNI (port 443/TLS) or HTTP Host header (port 80/HTTP).
    """
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        return
    
    total_packets = len(packets)
    print(f"Total packets: {total_packets}\n")
    
    analyzed_count = 0
    
    for idx, pkt in enumerate(packets, 1):
        # Convert packet to raw bytes
        raw_bytes = bytes(pkt)
        
        # Parse the packet
        parsed = parse(raw_bytes)
        if parsed is None:
            continue
        
        analyzed_count += 1
        
        # Determine protocol string
        protocol_str = "TCP" if parsed.has_tcp else "UDP" if parsed.has_udp else "?"
        
        # Print basic packet info
        print(f"[{idx}] {protocol_str} {parsed.src_ip}:{parsed.src_port} → {parsed.dst_ip}:{parsed.dst_port}", end="")
        
        # Extract domain information if available
        domain = None
        
        if parsed.dst_port == 443 and parsed.payload:
            domain = extract_sni(parsed.payload)
        elif parsed.dst_port == 80 and parsed.payload:
            domain = extract_http_host(parsed.payload)
        
        if domain:
            print(f" | DOMAIN: {domain}")
        else:
            print()
    
    print(f"\nTotal analyzed packets: {analyzed_count}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m src.pcap_reader <filepath>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    read_pcap(filepath)
