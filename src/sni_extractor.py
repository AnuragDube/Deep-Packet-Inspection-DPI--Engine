from typing import Optional


def extract_sni(payload: bytes) -> Optional[str]:
    """Extract SNI hostname from a TLS Client Hello payload."""
    if len(payload) < 43:
        return None

    # TLS Handshake record type 0x16 and ClientHello handshake type 0x01
    if payload[0] != 0x16 or payload[5] != 0x01:
        return None

    # Start at the beginning of the Client Hello data after the record header
    offset = 43

    # Session ID length and data
    if offset >= len(payload):
        return None
    session_id_length = payload[offset]
    offset += 1 + session_id_length
    if offset + 2 > len(payload):
        return None

    # Cipher suites length
    cipher_suites_length = int.from_bytes(payload[offset:offset + 2], "big")
    offset += 2 + cipher_suites_length
    if offset >= len(payload):
        return None

    # Compression methods length
    compression_methods_length = payload[offset]
    offset += 1 + compression_methods_length
    if offset + 2 > len(payload):
        return None

    # Extensions length
    extensions_length = int.from_bytes(payload[offset:offset + 2], "big")
    offset += 2
    extensions_end = offset + extensions_length
    if extensions_end > len(payload):
        return None

    while offset + 4 <= extensions_end:
        ext_type = int.from_bytes(payload[offset:offset + 2], "big")
        ext_length = int.from_bytes(payload[offset + 2:offset + 4], "big")
        offset += 4

        if offset + ext_length > extensions_end:
            return None

        if ext_type == 0x0000:  # Server Name Indication
            if ext_length < 5:
                return None
            sni_offset = offset
            sni_list_length = int.from_bytes(payload[sni_offset:sni_offset + 2], "big")
            sni_offset += 2
            if sni_offset + sni_list_length > offset + ext_length:
                return None

            if sni_offset >= len(payload):
                return None
            sni_type = payload[sni_offset]
            sni_offset += 1
            sni_name_length = int.from_bytes(payload[sni_offset:sni_offset + 2], "big")
            sni_offset += 2

            if sni_offset + sni_name_length > offset + ext_length:
                return None

            hostname_bytes = payload[sni_offset:sni_offset + sni_name_length]
            try:
                return hostname_bytes.decode("utf-8", errors="ignore")
            except UnicodeDecodeError:
                return None

        offset += ext_length

    return None


def extract_http_host(payload: bytes) -> Optional[str]:
    """Extract the Host header from HTTP payload bytes."""
    decoded = payload.decode("utf-8", errors="ignore")
    lines = decoded.split("\r\n")
    for line in lines:
        if line.lower().startswith("host:"):
            return line.split(":", 1)[1].strip()
    return None
