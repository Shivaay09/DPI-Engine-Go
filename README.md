# DPI-Engine-Go

A Deep Packet Inspection engine written in Go that analyzes network traffic captures, identifies applications by inspecting packet payloads, and filters traffic based on configurable blocking rules.

## What it does

Most firewalls only look at IP addresses and port numbers. This engine goes deeper — it reads inside the packet payload to identify *which application* is generating the traffic, even for encrypted HTTPS connections.

The key insight is that TLS (the encryption protocol behind HTTPS) sends the target hostname in plaintext during the initial handshake, in a field called the **Server Name Indication (SNI)**. This engine extracts that field to identify destinations like YouTube, TikTok, or Netflix before any encryption has taken place.

## How it works

```
input.pcap → [Ethernet → IP → TCP/UDP → Payload]
                                              ↓
                              TLS SNI / HTTP Host / DNS extraction
                                              ↓
                                    Flow classification
                                              ↓
                                      Rule matching
                                              ↓
                          forward → output.pcap  |  drop → discarded
```

Each packet is parsed layer by layer. Connections are tracked by their **five-tuple** (source IP, destination IP, source port, destination port, protocol) so that once a flow is identified and blocked, all subsequent packets of that connection are dropped instantly without re-inspection.

## Features

- **TLS SNI extraction** — parses TLS 1.x Client Hello bytes at the binary level to extract the target hostname from encrypted connections
- **HTTP Host header parsing** — extracts destinations from plaintext HTTP/1.x requests
- **DNS query extraction** — reads queried domain names from UDP port 53 packets
- **Stateful flow tracking** — connection state persists across packets; blocking decisions are made once per flow
- **Application classification** — identifies 23 applications including YouTube, TikTok, Netflix, Facebook, Instagram, Discord, GitHub, and more
- **Flexible blocking rules** — block by source IP, application name, domain (exact, wildcard `*.example.com`, or substring), or destination port
- **PCAP in/out** — reads standard `.pcap` files produced by Wireshark or tcpdump and writes filtered output in the same format
- **Zero external dependencies** — built entirely on the Go standard library

## Usage

```bash
# Build
go build -o dpi_engine .

# Run
./dpi_engine <input.pcap> <output.pcap> [options]

# Options
--block-ip     <ip>      Block all traffic from a source IP
--block-app    <app>     Block by application name
--block-domain <domain>  Block by domain (exact, wildcard, or substring)
--block-port   <port>    Block by destination port
```

## Examples

```bash
# Block YouTube and TikTok
./dpi_engine capture.pcap filtered.pcap --block-app YouTube --block-app TikTok

# Block a specific IP address
./dpi_engine capture.pcap filtered.pcap --block-ip 192.168.1.50

# Block all subdomains of facebook.com
./dpi_engine capture.pcap filtered.pcap --block-domain "*.facebook.com"

# Combine multiple rules
./dpi_engine capture.pcap filtered.pcap \
  --block-app Netflix \
  --block-domain tiktok \
  --block-ip 10.0.0.25
```

## Sample output

```
╔══════════════════════════════════════════════════════════════════╗
║                  DPI ENGINE v2.0 (Go)                            ║
╚══════════════════════════════════════════════════════════════════╝

[DPI] Processing packets...
[BLOCKED] 192.168.1.5 → 142.250.185.46 (YouTube [app: YouTube])

╔══════════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                           ║
╠══════════════════════════════════════════════════════════════════╣
║  Total Packets:          77                                      ║
║  Forwarded:              69                                      ║
║  Dropped:                 8                                      ║
║  Active Flows:           14                                      ║
╠══════════════════════════════════════════════════════════════════╣
║                    APPLICATION BREAKDOWN                         ║
╠══════════════════════════════════════════════════════════════════╣
║  HTTPS            39   50.6%  ##########                         ║
║  Unknown          16   20.8%  #####                              ║
║  YouTube           8   10.4%  ## (BLOCKED)                       ║
║  DNS               4    5.2%  #                                  ║
║  Facebook          3    3.9%                                     ║
╚══════════════════════════════════════════════════════════════════╝

[Detected Domains / SNIs]
  - www.youtube.com → YouTube
  - www.facebook.com → Facebook
  - github.com → GitHub
```

## Project structure

```
.
├── main.go      # CLI entry point and argument parsing
├── engine.go    # Core processing loop and packet pipeline
├── parser.go    # Ethernet / IPv4 / TCP / UDP header dissection
├── sni.go       # TLS SNI, HTTP Host, and DNS payload extraction
├── rules.go     # Blocking rule manager with RWMutex locking
├── pcap.go      # PCAP file reading and writing
├── types.go     # Shared types: FiveTuple, AppType, Flow, SNIToAppType
└── go.mod
```

## Supported applications

`Google` `YouTube` `Facebook` `Instagram` `WhatsApp` `Twitter/X` `Netflix` `Amazon` `Microsoft` `Apple` `Telegram` `TikTok` `Spotify` `Zoom` `Discord` `GitHub` `Cloudflare` `HTTP` `HTTPS` `DNS` `TLS` `QUIC`

## Requirements

- Go 1.21+
- A `.pcap` file (captured with Wireshark, tcpdump, or generated with Scapy)

---

> **Note:** This tool is intended for educational use and authorized network analysis only. Always ensure you have permission before capturing or inspecting network traffic.
