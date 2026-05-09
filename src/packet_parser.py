import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedPacket:
    """Represents a parsed network packet with extracted headers and payload."""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    payload: bytes = b""
    raw: bytes = b""


def ip_to_str(raw_bytes: bytes) -> str:
    """Convert 4 bytes to IP address string format (e.g., '192.168.1.1')."""
    if len(raw_bytes) < 4:
        return ""
    return ".".join(str(b) for b in raw_bytes[:4])


def parse(raw_bytes: bytes) -> Optional[ParsedPacket]:
    """
    Parse a raw packet and extract packet information.
    
    Parses Ethernet frame and IPv4 header, then TCP or UDP transport layer.
    Returns None if packet is malformed or not IPv4.
    """
    # Minimum Ethernet frame + IPv4 header is 14 + 20 = 34 bytes
    if len(raw_bytes) < 34:
        return None
    
    # Check EtherType at bytes 12-13 for IPv4 (0x0800)
    ether_type = struct.unpack("!H", raw_bytes[12:14])[0]
    if ether_type != 0x0800:
        return None
    
    # Parse IPv4 header starting at byte 14
    ip_header_start = 14
    
    # Get IHL (Header Length) from bottom 4 bits of byte 14 (offset 0 from IP start)
    # IHL is in 32-bit words, multiply by 4 to get bytes
    version_ihl = raw_bytes[ip_header_start]
    ihl = (version_ihl & 0x0F) * 4
    
    # Get protocol from byte 23 (offset 9 from IP start)
    protocol = raw_bytes[ip_header_start + 9]
    
    # Get src IP from bytes 26-29 (offset 12-15 from IP start)
    src_ip = ip_to_str(raw_bytes[ip_header_start + 12:ip_header_start + 16])
    
    # Get dst IP from bytes 30-33 (offset 16-19 from IP start)
    dst_ip = ip_to_str(raw_bytes[ip_header_start + 16:ip_header_start + 20])
    
    # Create packet object
    packet = ParsedPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        protocol=protocol,
        raw=raw_bytes
    )
    
    # Parse transport layer (TCP/UDP)
    transport_start = ip_header_start + ihl
    
    if protocol == 6:  # TCP
        if len(raw_bytes) < transport_start + 4:
            return packet
        
        src_port, dst_port = struct.unpack("!HH", raw_bytes[transport_start:transport_start + 4])
        packet.src_port = src_port
        packet.dst_port = dst_port
        packet.has_tcp = True
        
        # TCP payload starts after TCP header
        # Data offset is in top 4 bits of byte 12 of TCP header, in 32-bit words
        if len(raw_bytes) >= transport_start + 12:
            data_offset = (raw_bytes[transport_start + 12] >> 4) * 4
            payload_start = transport_start + data_offset
            packet.payload = raw_bytes[payload_start:] if payload_start < len(raw_bytes) else b""
    
    elif protocol == 17:  # UDP
        if len(raw_bytes) < transport_start + 4:
            return packet
        
        src_port, dst_port = struct.unpack("!HH", raw_bytes[transport_start:transport_start + 4])
        packet.src_port = src_port
        packet.dst_port = dst_port
        packet.has_udp = True
        
        # UDP payload starts after UDP header (8 bytes)
        payload_start = transport_start + 8
        packet.payload = raw_bytes[payload_start:] if payload_start < len(raw_bytes) else b""
    
    return packet
