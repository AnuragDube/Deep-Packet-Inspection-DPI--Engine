# Module for managing DPI rules and patterns

from typing import Set


class RuleEngine:
    """Manages blocking rules for IP addresses, applications, and domains."""

    def __init__(self):
        """Initialize the rule engine with empty rule sets."""
        self.blocked_ips: Set[str] = set()
        self.blocked_apps: Set[str] = set()
        self.blocked_domains: list[str] = []

    def add_blocked_ip(self, ip: str) -> None:
        """Add an IP address to the blocked list."""
        self.blocked_ips.add(ip)
        print(f"[Rules] Blocking IP: {ip}")

    def add_blocked_app(self, app: str) -> None:
        """Add an application to the blocked list."""
        self.blocked_apps.add(app.lower())
        print(f"[Rules] Blocking app: {app}")

    def add_blocked_domain(self, domain: str) -> None:
        """Add a domain pattern to the blocked list."""
        self.blocked_domains.append(domain.lower())
        print(f"[Rules] Blocking domain: {domain}")

    def is_blocked(self, src_ip: str, app: str, sni: str) -> bool:
        """
        Check if traffic should be blocked based on current rules.

        Returns True if the traffic matches any blocking rule.
        """
        # Check blocked IP addresses
        if src_ip in self.blocked_ips:
            return True

        # Check blocked applications
        if app.lower() in self.blocked_apps:
            return True

        # Check blocked domains in SNI
        if sni:
            sni_lower = sni.lower()
            for domain in self.blocked_domains:
                if domain in sni_lower:
                    return True

        return False
