# Module for tracking and managing network flows

from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional

# Type alias for a 5-tuple flow identifier
FiveTuple = Tuple[str, str, int, int, int]  # src_ip, dst_ip, src_port, dst_port, protocol


@dataclass
class Flow:
    """Represents a network flow with aggregated statistics."""
    five_tuple: tuple
    packet_count: int = 0
    byte_count: int = 0
    sni: str = ""
    app: str = "Unknown"
    blocked: bool = False


class FlowTracker:
    """Tracks network flows and aggregates packet statistics."""

    def __init__(self):
        """Initialize the flow tracker with an empty flows dictionary."""
        self.flows: Dict[Tuple, Flow] = {}

    def _make_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> Tuple:
        """
        Create a normalized flow key that handles bidirectional flows.

        Normalizes the direction by sorting IP addresses and ports so that
        both directions of a connection map to the same key.
        """
        # Create both possible tuples
        forward = (src_ip, dst_ip, src_port, dst_port, proto)
        reverse = (dst_ip, src_ip, dst_port, src_port, proto)

        # Return the lexicographically smaller tuple as the key
        return min(forward, reverse)

    def get_or_create(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: int) -> Flow:
        """
        Get an existing flow or create a new one for the given 5-tuple.

        Returns the Flow object for tracking packet statistics.
        """
        key = self._make_key(src_ip, dst_ip, src_port, dst_port, proto)

        if key not in self.flows:
            self.flows[key] = Flow(five_tuple=key)

        return self.flows[key]

    def update(self, flow: Flow, payload_len: int, sni: str, app: str) -> None:
        """
        Update flow statistics with new packet information.

        Increments packet and byte counts, and updates SNI/app info if not already set.
        """
        flow.packet_count += 1
        flow.byte_count += payload_len

        # Set SNI only if it's not empty and not already set
        if sni and not flow.sni:
            flow.sni = sni

        # Set app only if it's not Unknown and not already set
        if app != "Unknown" and flow.app == "Unknown":
            flow.app = app

    def all_flows(self):
        """Return all tracked flows."""
        return self.flows.values()
