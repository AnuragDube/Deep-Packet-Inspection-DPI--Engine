# Module for classifying applications based on packet analysis

APP_PATTERNS = [
    ("YouTube",  ["youtube.com", "googlevideo.com", "ytimg.com"]),
    ("Facebook", ["facebook.com", "fbcdn.net", "instagram.com"]),
    ("Google",   ["google.com", "googleapis.com", "gstatic.com"]),
    ("Twitter",  ["twitter.com", "twimg.com", "t.co"]),
    ("Netflix",  ["netflix.com", "nflxvideo.net"]),
    ("TikTok",   ["tiktok.com", "tiktokcdn.com"]),
    ("GitHub",   ["github.com", "githubusercontent.com"]),
    ("Amazon",   ["amazon.com", "amazonaws.com"]),
]


def classify(sni: str, dst_port: int, protocol: int) -> str:
    """Classify traffic based on SNI and destination port."""
    if sni:
        sni_lower = sni.lower()
        for app_name, patterns in APP_PATTERNS:
            for pattern in patterns:
                if pattern in sni_lower:
                    return app_name

    if dst_port == 443:
        return "HTTPS"
    if dst_port == 80:
        return "HTTP"
    if dst_port == 53:
        return "DNS"

    return "Unknown"