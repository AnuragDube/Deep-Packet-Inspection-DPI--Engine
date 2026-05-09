# Deep Packet Inspection (DPI) Engine

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/) [![License: MIT](https://img.shields.io/badge/license-MIT-green)](https://opensource.org/licenses/MIT)

Ever wondered how your ISP knows you're watching YouTube even on HTTPS? This project shows you exactly how — and lets you build it yourself.

A Python-based network traffic analyzer that inspects packets, extracts domains from HTTPS/HTTP traffic, classifies applications, and filters network flows based on blocking rules.

## 🚀 Quick Demo

```bash
python main.py tests/test_dpi.pcap --block-app YouTube --block-app Facebook --block-app TikTok
```

```text
[Rules] Blocking app: YouTube
[Rules] Blocking app: Facebook
[Rules] Blocking app: TikTok
Processing 77 packets from tests/test_dpi.pcap

DPI ENGINE REPORT
Total packets: 77
Forwarded: 73
Dropped: 4

Application Breakdown:
  Facebook: 2 flows
  Twitter: 2 flows
  YouTube: 1 flows
  Netflix: 1 flows
  TikTok: 1 flows

Detected Domains:
  www.youtube.com -> YouTube
  www.facebook.com -> Facebook
  www.netflix.com -> Netflix
  www.tiktok.com -> TikTok
  github.com -> GitHub
```

## 🔍 What is DPI?

Deep Packet Inspection (DPI) is the process of examining the contents of network packets beyond the usual source/destination headers. It looks into the payload to identify app behavior, domain names, and protocol details.

| What it is | Why it matters |
|---|---|
| Packet-level inspection | Finds app-level data, not just IP addresses |
| SNI extraction | Reveals HTTPS domains during the TLS handshake |
| Flow filtering | Blocks traffic by app, IP, or domain |
| Real-world use | Used by ISPs, firewalls, parental controls, and security teams |

### 🔐 How SNI Works

During TLS setup, the browser sends the requested hostname in plain text so the server can select the right certificate. That means HTTPS hides the content, but not the destination domain.

```text
Browser                                   Server
   | -------- ClientHello (SNI) --------> |
   | <------- ServerHello / Certificate -- |
   | -------- Encrypted Application ----> |
```

## ⚙️ How It Works

| Step | What Happens | File Responsible |
|---|---|---|
| 1 | Read a PCAP file using `scapy` (77 packets in the test file) | `main.py` / `src/pcap_reader.py` |
| 2 | Parse Ethernet header (14 bytes), IPv4 header (20 bytes), TCP/UDP header (20/8 bytes) manually using `struct` | `src/packet_parser.py` |
| 3 | Extract SNI from TLS Client Hello on port 443 or `Host` from HTTP on port 80 | `src/sni_extractor.py` |
| 4 | Classify traffic into apps using domain pattern matching | `src/app_classifier.py` |
| 5 | Track flows by 5-tuple and normalize both directions with `min()` | `src/flow_tracker.py` |
| 6 | Apply flow-level blocking rules so future packets are dropped | `src/rule_manager.py` |
| 7 | Print a report with total/forwarded/dropped counts, app breakdown, and domains | `main.py` |

## 🏗️ Project Architecture

```text
┌─────────────┐    ┌──────────────┐    ┌───────────────┐    ┌───────────────┐
│  PCAP File  │ →  │ Packet Parser│ →  │ SNI Extractor │ →  │ App Classifier│
└─────────────┘    └──────────────┘    └───────────────┘    └───────────────┘
                         │                        │
                         ▼                        ▼
                    ┌───────────────┐    ┌────────────────┐
                    │ Flow Tracker  │ →  │ Rule Manager   │
                    └───────────────┘    └────────────────┘
                         │
                         ▼
                    Report + Filtered Output
```

| File | Purpose |
|---|---|
| `main.py` | Entry point, wires all modules together, argparse CLI |
| `src/packet_parser.py` | Parses Ethernet/IPv4/TCP/UDP headers from raw bytes |
| `src/sni_extractor.py` | Extracts domain from TLS Client Hello SNI extension |
| `src/app_classifier.py` | Maps domain patterns to app names (YouTube, Netflix etc.) |
| `src/flow_tracker.py` | Groups packets into flows by 5-tuple, tracks stats |
| `src/rule_manager.py` | Manages IP, app, and domain blocking rules |

## 🧩 Blocking Rules

| Rule Type | Flag | Example | What It Blocks |
|---|---|---|---|
| App | `--block-app` | `--block-app YouTube` | Any flow classified as that app |
| IP | `--block-ip` | `--block-ip 192.168.1.50` | Traffic from that source IP |
| Domain | `--block-domain` | `--block-domain tiktok` | Any SNI matching the domain pattern |

## 📁 File Structure

```
Deep-Packet-Inspection-DPI--Engine/
├── src/
│   ├── __init__.py
│   ├── packet_parser.py
│   ├── pcap_reader.py
│   ├── sni_extractor.py
│   ├── app_classifier.py
│   ├── flow_tracker.py
│   └── rule_manager.py
├── tests/
│   └── test_dpi.pcap
├── main.py
├── requirements.txt
├── .gitignore
└── README.md
```

## ⚡ Installation

```bash
git clone https://github.com/AnuragDube/Deep-Packet-Inspection-DPI--Engine.git
cd Deep-Packet-Inspection-DPI--Engine
pip install -r requirements.txt
```

## 🧪 Usage

**Basic run:**

```bash
python main.py tests/test_dpi.pcap
```

**Block YouTube:**

```bash
python main.py tests/test_dpi.pcap --block-app YouTube
```

**Block multiple apps:**

```bash
python main.py tests/test_dpi.pcap --block-app YouTube --block-app Facebook --block-app TikTok
```

**Block by IP:**

```bash
python main.py tests/test_dpi.pcap --block-ip 192.168.1.50
```

**Block by domain pattern:**

```bash
python main.py tests/test_dpi.pcap --block-domain tiktok
```

**Save filtered output:**

```bash
python main.py tests/test_dpi.pcap output.pcap --block-app YouTube
```

## 📊 Sample Output

```text
[Rules] Blocking app: YouTube
[Rules] Blocking app: Facebook
[Rules] Blocking app: TikTok
Processing 77 packets from tests/test_dpi.pcap

DPI ENGINE REPORT
Total packets: 77
Forwarded: 73
Dropped: 4

Application Breakdown:
  Facebook: 2 flows
  Twitter: 2 flows
  YouTube: 1 flows
  Netflix: 1 flows
  TikTok: 1 flows

Detected Domains:
  www.youtube.com -> YouTube
  www.facebook.com -> Facebook
  www.netflix.com -> Netflix
  www.tiktok.com -> TikTok
  github.com -> GitHub
```

## 🎓 What I Learned

| Concept | What I Understood |
|---|---|
| Network protocol layers | Ethernet, IPv4, TCP/UDP header structure |
| Byte-level parsing | Manual packet parsing using Python `struct` |
| TLS/SNI | How SNI leaks domain names in HTTPS |
| Flow tracking | Stateful tracking using 5-tuple dictionary keys |
| Blocking logic | Flow-level rules are more stable than per-packet rules |
| Python architecture | Using dataclasses, argparse, and type hints effectively |
| Version control | Writing meaningful Git commits for progress tracking |
| Verification | Using Wireshark to confirm packet analysis results |

## 🛠️ Tech Stack

| Tool | Purpose | Why Used |
|---|---|---|
| Python 3.8+ | Core implementation | Simple, expressive network parsing |
| Scapy 2.5+ | PCAP parsing | Reliable packet file handling |
| Wireshark | Packet visualization | Manual verification and debugging |
| `struct` | Byte-level unpacking | Low-level packet field extraction |
| `dataclasses` | Structured data | Clean flow and packet models |
| `argparse` | CLI parsing | User-friendly command-line interface |
| `collections` | Counters and aggregation | Reporting and app breakdown |
| `typing` | Type hints | Code clarity and maintainability |

Built as a learning project to understand network protocols and packet analysis from scratch.