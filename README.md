# Wireshark Traffic Analysis Lab

A hands-on network traffic analysis lab demonstrating how DNS resolution, a TCP three-way handshake, and TLS negotiation appear in a real Wireshark capture.

## Security Notice

This repository is an educational network-analysis lab for authorized traffic
only. It is not production monitoring guidance. Packet captures can expose
addresses, hostnames, sessions, and personal activity, so the raw capture is
intentionally excluded and must not be published without review and
sanitization. No intentionally vulnerable service or real credential is
included.

Do not deploy this project in production.

## Lab objectives

- Capture live network traffic on a Windows Wi-Fi interface.
- Identify DNS A and AAAA queries and responses.
- Trace a complete TCP three-way handshake.
- Inspect a TLS Client Hello and Server Hello.
- Explain well-known and ephemeral port usage.
- Document findings with reproducible Wireshark display filters.

## Controlled test

The capture covered a 29.6-second window. During that window, the client resolved `example.com` and made an HTTPS `HEAD /` request. The connection negotiated TLS 1.3 and returned `HTTP/1.1 200 OK`.

The detailed, frame-by-frame results are in [WIRESHARK_TRAFFIC_ANALYSIS.md](WIRESHARK_TRAFFIC_ANALYSIS.md).

## Key evidence

| Layer | Evidence |
|---|---|
| DNS | A and AAAA lookups for `example.com` over UDP port 53 |
| TCP | SYN, SYN/ACK, and ACK in frames 1865-1867 |
| TLS | Client Hello in frame 1868 and Server Hello in frame 1870 |
| Encryption | TLS 1.3 with `TLS_AES_256_GCM_SHA384` |
| HTTPS | Client ephemeral TCP port 13815 connected to server port 443 |

## Useful filters

```text
dns.qry.name == "example.com"
tcp.flags.syn == 1 && tcp.flags.ack == 0
tcp.stream == 67
tls.handshake.extensions_server_name == "example.com"
tcp.stream == 67 && tls.handshake.type == 2
udp.port == 53 || tcp.port == 443
```

Additional copy-ready filters are available in [DISPLAY_FILTERS.txt](DISPLAY_FILTERS.txt).

## Privacy and evidence handling

The original packet capture is intentionally excluded from this public repository. Even a controlled capture can contain unrelated background conversations, local addressing, host metadata, and DNS activity. The report retains the packet numbers and decoded protocol evidence needed to reproduce the analysis without publishing the raw PCAP.

## Tools

- Wireshark/Dumpcap 4.6.4
- TShark for display-filter validation and packet extraction
- Windows 11

## Skills demonstrated

Network traffic capture, protocol analysis, DNS, TCP/IP, IPv4/IPv6, TLS, Wireshark display filters, evidence handling, and security documentation.
