# Wireshark Traffic Analysis

## Objective

Capture a short sample of real network traffic and identify DNS resolution, a TCP three-way handshake, TLS negotiation, and the ports used by a controlled HTTPS connection.

## Capture scope and method

- Capture date: September 12, 2026
- Interface: Wi-Fi (`Killer(R) Wi-Fi 6E AX1675x 160MHz Wireless Network Adapter`)
- Capture tool: Dumpcap/Wireshark 4.6.4
- Capture duration: 29.568638 seconds
- Capture file: `controlled-traffic.pcapng`
- Packets captured: 2,261
- Packets dropped: 0
- Capture size: 1,815 kB (1,738 kB of packet data)
- SHA-256: `20643cbf7293ce584cae86b00222eac475d7e61545d0cf4138939e71a84e9684`

The controlled activity was a DNS lookup for `example.com` followed by an HTTPS `HEAD /` request. The client reported a successful TLS 1.3 session and an HTTP `200 OK` response. Because TLS encrypts application data, the HTTP status and headers are not readable directly in the packet capture without session keys.

The capture also contains normal background traffic from the host. The findings below are limited to the controlled `example.com` activity.

## DNS findings

Immediately before the HTTPS connection, the client queried its IPv6 DNS resolver for both IPv4 and IPv6 addresses:

| Frame | Time (s) | Source port | Destination port | DNS detail |
|---:|---:|---:|---:|---|
| 1861 | 21.895244 | 49531/UDP | 53/UDP | A query for `example.com` |
| 1862 | 21.895330 | 62256/UDP | 53/UDP | AAAA query for `example.com` |
| 1863 | 21.897485 | 53/UDP | 49531/UDP | A response: `104.20.23.154`, `172.66.147.243` |
| 1864 | 21.897526 | 53/UDP | 62256/UDP | AAAA response: `2606:4700:10::ac42:93f3`, `2606:4700:10::6814:179a` |

The A response arrived in about 2.24 ms and the AAAA response in about 2.20 ms. The subsequent TCP connection selected IPv6 address `2606:4700:10::ac42:93f3`.

An explicit test lookup to Cloudflare resolver `1.1.1.1` is also visible in frames 1445-1448. It used UDP client ports 51186 and 51187 and returned the same A and AAAA address sets.

## TCP three-way handshake

Wireshark assigned the controlled HTTPS flow to `tcp.stream == 67`.

| Step | Frame | Time (s) | Direction | Flags | Relative sequence/acknowledgment |
|---:|---:|---:|---|---|---|
| 1 | 1865 | 21.899533 | Client `13815` -> Server `443` | SYN | Seq=0, Ack=0 |
| 2 | 1866 | 21.927698 | Server `443` -> Client `13815` | SYN, ACK | Seq=0, Ack=1 |
| 3 | 1867 | 21.927844 | Client `13815` -> Server `443` | ACK | Seq=1, Ack=1 |

The SYN-to-SYN/ACK round-trip time was about 28.17 ms. The three-way handshake completed in about 28.31 ms, establishing a reliable TCP connection before TLS negotiation began.

## TLS findings

| Frame | TLS event | Evidence |
|---:|---|---|
| 1868 | Client Hello | SNI is `example.com`; client offers TLS cipher suites and starts negotiation over TCP 443 |
| 1870 | Server Hello | `supported_versions` selects TLS 1.3; selected cipher is `TLS_AES_256_GCM_SHA384` (`0x1302`); key share is X25519 |
| 1872-1879 | Encrypted TLS records | Handshake completion and HTTP request/response data appear as encrypted TLS 1.3 application data |

Wireshark may label the Client Hello record as TLS 1.2 because the record-layer and legacy-version field use `0x0303` for compatibility. The Server Hello's `supported_versions` extension is authoritative and shows that TLS 1.3 was negotiated.

The server sent `FIN, ACK` in frame 1880. The client acknowledged the close and then sent `RST, ACK` in frame 1883 as the local socket was torn down. This is not evidence that the HTTPS request failed; the client had already received `HTTP/1.1 200 OK`.

## Ports and protocol roles

| Port | Transport | Role in this capture |
|---:|---|---|
| 53 | UDP | DNS queries and responses |
| 443 | TCP | HTTPS/TLS service on `example.com` |
| 49531, 62256 | UDP | Temporary client ports for the system DNS queries |
| 51186, 51187 | UDP | Temporary client ports for the explicit `1.1.1.1` DNS test |
| 13815 | TCP | Temporary client port for the controlled HTTPS connection |

Client-side ephemeral ports identify individual conversations and allow multiple simultaneous connections to the same well-known server port.

## Capture-wide observations

- IPv6 dominated the sample: 2,197 of 2,261 frames. IPv4 accounted for 62 frames; the remaining frames were ARP/VLAN traffic.
- TCP dominated the capture: 2,229 frames. UDP accounted for 26 frames, including 16 DNS frames.
- Wireshark decoded 632 frames as TLS across all background and controlled conversations.
- The controlled HTTPS stream contains 19 frames (1865-1883).

These totals describe the whole 29.6-second sample, not only the controlled connection.

## Useful Wireshark display filters

```text
# All DNS traffic
dns

# Queries or responses for the controlled hostname
dns.qry.name == "example.com"

# Initial TCP SYN packets, excluding SYN/ACK
tcp.flags.syn == 1 && tcp.flags.ack == 0

# The exact controlled TCP/TLS conversation
tcp.stream == 67

# TLS Client Hello containing the requested hostname
tls.handshake.extensions_server_name == "example.com"

# TLS Server Hello packets in the controlled stream
tcp.stream == 67 && tls.handshake.type == 2

# Traffic using the principal well-known ports
udp.port == 53 || tcp.port == 443
```

## Conclusion

The capture shows the complete progression of a secure web connection: DNS mapped `example.com` to IPv4 and IPv6 addresses, the client selected an IPv6 address, TCP established the session with a three-way handshake, and TLS 1.3 negotiated encryption on destination port 443. DNS was visible in plaintext on UDP port 53, while the HTTP request and response were protected inside encrypted TLS application records.

## Privacy note

Packet captures can contain host addresses, DNS names, and unrelated background traffic. Treat `controlled-traffic.pcapng` as potentially sensitive and share only when required. Apply the display filters above before examining or exporting packets for screenshots.
