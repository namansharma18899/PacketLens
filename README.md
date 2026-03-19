# PacketLens

A **Deep Packet Inspection (DPI)** tool that reads PCAP captures, classifies traffic by application (via TLS SNI and HTTP Host), and filters packets based on rules. It’s a learning/reference implementation—not intended for production use.


## WHY 🤨 is it Required !!!
- **A fun tool** to look into our packets an decide where all that data goes !! 

## What it does 🔬

- **Reads PCAP files** (e.g. from Wireshark) and parses Ethernet → IPv4 → TCP/UDP.
- **Classifies flows** by extracting **SNI** from TLS Client Hello (HTTPS) and **Host** from plain HTTP.
- **Maps domains to app types** (YouTube, Facebook, Google, Netflix, etc.) using pattern matching.
- **Applies block rules** by source IP, app type, or domain (substring).
- **Writes a filtered PCAP** and prints a summary report (forwarded/dropped, app breakdown, detected domains).

## Requirements 🗑️

- **Python 3.8+**
- No third-party dependencies for the main app; tests use **pytest**.

## Installation ⚙️

```bash
git clone <repo-url>
cd PacketLens
pip install -r requirements.txt   # optional, for tests
```

## Usage

```bash
python main.py <input.pcap> <output.pcap> [options]
```

### Examples

```bash
# Filter only (no blocking)
python main.py capture.pcap filtered.pcap

# Block by app
python main.py capture.pcap out.pcap --block-app YouTube --block-app TikTok

# Block by source IP
python main.py capture.pcap out.pcap --block-ip 192.168.1.50

# Block by domain (substring match)
python main.py capture.pcap out.pcap --block-domain facebook

# Combine rules, quiet output
python main.py capture.pcap out.pcap --block-app YouTube --block-domain twitter -q
```

### Options

| Option | Description |
|--------|-------------|
| `--block-ip IP` | Block all traffic from this source IP (repeatable). |
| `--block-app APP` | Block by app name (e.g. YouTube, Facebook, Google). |
| `--block-domain DOM` | Block if SNI/host contains this string (repeatable). |
| `-q`, `--quiet` | Less output (no banner/report). |

## Project structure

```
PacketLens/
├── main.py           # CLI entry point
├── dpi_engine.py     # Pipeline: read → parse → classify → filter → write
├── dpi_types.py      # FiveTuple, AppType, Flow, IP/SNI helpers
├── pcap_reader.py    # PCAP file read (global header, packet records)
├── packet_parser.py  # Ethernet / IPv4 / TCP-UDP parsing
├── sni_extractor.py  # TLS SNI + HTTP Host extraction
├── rule_manager.py   # Block rules (IP, app, domain)
├── requirements.txt  # pytest for tests
├── Dockerfile        # Run tests or app in container
├── pyproject.toml    # pytest config (pythonpath)
└── tests/
    ├── test_dpi_types.py
    ├── test_pcap_reader.py
    ├── test_packet_parser.py
    ├── test_sni_extractor.py
    ├── test_rule_manager.py
    ├── test_dpi_engine.py
    └── helpers.py    # Shared test packet builders
```

## Running tests

From the project root:

```bash
pip install -r requirements.txt
pytest tests/ -v
```

With project root on `PYTHONPATH`:

```bash
PYTHONPATH=. pytest tests/ -v
```

## Docker

Build and run tests:

```bash
docker build -t packetlens .
docker run --rm packetlens
```

Run the DPI engine on host files by mounting a directory:

```bash
docker run --rm -v "$(pwd):/data" packetlens python main.py /data/input.pcap /data/output.pcap --block-app YouTube
```

(Override the default `CMD` so the container runs `main.py` instead of `pytest`.)

## How it works (short)

1. **PcapReader** reads the PCAP global header and packet records (with byte-order handling).
2. **PacketParser** parses each packet into Ethernet, IP, and TCP/UDP and exposes a 5-tuple and payload.
3. Flows are keyed by 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol).
4. For port 443, **SNIExtractor** parses the TLS Client Hello and extracts the SNI hostname.
5. For port 80, **HTTPHostExtractor** finds the `Host` header.
6. **sni_to_app_type()** maps hostnames to app labels (e.g. `youtube.com` → YouTube).
7. **RuleManager** decides whether to block (IP, app, or domain rule).
8. Non-blocked packets are written to the output PCAP; a text report is printed.

## Disclaimer

PacketLens is for **education and experimentation**. It is not a production-grade DPI or security product. Use at your own risk.

## Support 

If you like my work please drop a ⭐️
