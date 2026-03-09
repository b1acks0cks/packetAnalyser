# Packet Analyzer (NetDragon)


A command-line network packet analyzer written in pure C, capable of capturing and parsing network traffic at multiple protocol layers.

## Overview

NetDragon is a lightweight packet analysis tool that leverages libpcap to capture and dissect network packets in real-time. It provides detailed parsing of Ethernet frames, IPv4/IPv6 packets, and TCP/UDP segments with support for various network protocols.

## Features

- **Multi-Layer Protocol Parsing**
  - Link Layer: Ethernet II, Linux Cooked Capture (SLL)
  - Network Layer: IPv4, IPv6
  - Transport Layer: TCP, UDP
  - Application Layer: Raw payload extraction

- **Comprehensive Protocol Support**
  - 40+ EtherType protocols (IPv4, IPv6, ARP, VLAN, PPPoE, etc.)
  - IPv4 features: DSCP, ECN, fragmentation, options
  - IPv6 features: Traffic class, flow labels, extension headers
  - TCP features: All flags, sequence/ack numbers, options, window size
  - UDP: Basic datagram parsing

- **Flexible Packet Capture**
  - Interface selection
  - BPF (Berkeley Packet Filter) support
  - Raw byte capture mode
  - Complete parsed scan mode

## Project Structure

```
packetAnalyser/
├── main.c                      # Main program entry point
├── makefile                    # Build configuration
├── ethernet/                   # Ethernet frame parsing
│   ├── ethernetparse.c
│   └── ethernetparse.h
├── ipv4/                       # IPv4 packet parsing
│   ├── ipv4parse.c
│   ├── ipv4parse.h
│   ├── ipv4.h
│   └── get/                    # IPv4 field decoders
│       ├── dscpcodes.c/h       # DSCP class decoder
│       ├── ecn.c/h             # ECN decoder
│       ├── flags.c/h           # IP flags decoder
│       ├── protocols.c/h       # Protocol number decoder
│       └── versions.c/h        # IP version decoder
├── ipv6/                       # IPv6 packet parsing
│   ├── ipv6parse.c
│   ├── ipv6parse.h
│   ├── ipv6.h
│   └── get/                    # IPv6 field decoders
│       ├── dscp.c/h
│       ├── ecnv6.c/h
│       ├── v6protocols.c/h
│       └── versions6.c/h
├── networklayer/               # Transport layer parsing
│   ├── tcpparse.c              # TCP segment parser
│   ├── tcpparse.h
│   ├── udpparse.c              # UDP datagram parser
│   ├── udpparse.h
│   ├── getflags.c              # TCP flags decoder
│   └── getflags.h
├── linuxcookedcaptures/        # Linux SLL support
│   ├── linuxcookedparse.c
│   └── linuxcookedparse.h
└── raw/                        # Raw byte capture
    ├── readlivebytes.c
    └── readlivebytes.h
```

## Prerequisites

- GCC compiler
- libpcap development library
- Linux operating system (recommended)

### Installing Dependencies

**Debian/Ubuntu:**
```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install gcc make libpcap-devel
```

**Arch Linux:**
```bash
sudo pacman -S gcc make libpcap
```

## Building

1. Navigate to the project directory:
```bash
cd packetAnalyser
```

2. Compile the project:
```bash
make
```

This will create the `netdragon` executable.

## Usage

### Basic Commands

**List Available Network Interfaces:**
```bash
sudo ./netdragon --list-interfaces
```

**Capture Raw Bytes:**
```bash
sudo ./netdragon -i <interface> raw
```

**Complete Parsed Scan:**
```bash
sudo ./netdragon -i <interface> complete
```

**Apply BPF Filter:**
```bash
sudo ./netdragon -i <interface> -filter "tcp port 80" complete
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--list-interfaces` | Display all available network interfaces |
| `-i <interface>` | Specify the network interface to capture on |
| `-filter <expression>` | Apply a BPF filter expression |
| `raw` | Capture and display raw packet bytes |
| `complete` | Perform full protocol parsing and display |

### Usage Examples

**Monitor HTTP traffic:**
```bash
sudo ./netdragon -i eth0 -filter "tcp port 80" complete
```

**Capture DNS queries:**
```bash
sudo ./netdragon -i wlan0 -filter "udp port 53" complete
```

**Monitor all TCP traffic:**
```bash
sudo ./netdragon -i eth0 -filter "tcp" complete
```

**Capture IPv6 traffic only:**
```bash
sudo ./netdragon -i eth0 -filter "ip6" complete
```

### BPF Filter Examples

The `-filter` option accepts standard Berkeley Packet Filter expressions:

- `host 192.168.1.1` - Traffic to/from specific host
- `net 192.168.0.0/24` - Traffic to/from specific network
- `tcp port 443` - HTTPS traffic
- `udp` - All UDP traffic
- `icmp` - ICMP packets only
- `vlan` - VLAN-tagged traffic
- `ether host aa:bb:cc:dd:ee:ff` - Specific MAC address

Combine filters with logical operators:
- `tcp and port 80` - TCP traffic on port 80
- `host 10.0.0.1 and (port 80 or port 443)` - HTTP/HTTPS to specific host
- `not tcp` - All non-TCP traffic

## Output Format

### Complete Scan Mode

The complete scan displays parsed information in this format:

```
**********
Frame aa:bb:cc:dd:ee:ff > 11:22:33:44:55:66
Ethertype: Internet Protocol version 4 (IPv4)
Network layer: 192.168.1.100 > 93.184.216.34
Transport layer: 54321 > 80
 Checksum: a3f5
Payload:
GET / HTTP/1.1
Host: example.com
...
```

### Parsed Information Includes:

**Ethernet Layer:**
- Source and destination MAC addresses
- EtherType (protocol identifier)
- 802.1Q VLAN tags (if present)

**IPv4 Layer:**
- Source and destination IP addresses
- Version, IHL (header length)
- DSCP (Differentiated Services Code Point)
- ECN (Explicit Congestion Notification)
- Total length, identification
- Flags (DF, MF, Reserved)
- Fragment offset
- TTL (Time to Live)
- Protocol (TCP/UDP/etc.)
- Header checksum
- Options (if present)

**IPv6 Layer:**
- Source and destination IPv6 addresses
- Version, traffic class
- Flow label
- Payload length
- Next header
- Hop limit

**TCP Layer:**
- Source and destination ports
- Sequence and acknowledgment numbers
- Data offset (header length)
- Flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR)
- Window size
- Checksum
- Urgent pointer
- Options (if present)

**UDP Layer:**
- Source and destination ports
- Length
- Checksum

**Application Payload:**
- Raw payload data in ASCII/hex format

## Supported Protocols

### EtherTypes (40+)
IPv4, IPv6, ARP, RARP, VLAN (802.1Q), PPPoE, MPLS, EAP over LAN, Wake-on-LAN, AppleTalk, IPX, and many more.

### IP Protocols
TCP, UDP, ICMP, ICMPv6, and protocol number-based identification.

### Link Layer Types
- DLT_EN10MB (Ethernet II)
- DLT_LINUX_SLL (Linux Cooked Capture)

## Known Limitations

- IPv6 extension header parsing is limited
- Linux Cooked Capture mode supports link-layer only
- Application layer protocol dissection is basic (raw payload only)
- No packet reassembly for fragmented packets
- Limited support for exotic protocols
- Requires root/sudo privileges for packet capture

## Memory Management

The parser allocates memory dynamically for parsed structures. Free functions are provided:
- `free_eth()` - Free Ethernet headers
- `free_INET_V4_HEADERS()` - Free IPv4 headers
- `free_INET_V6_HEADERS()` - Free IPv6 headers
- `free_tcp_headers()` - Free TCP headers
- `free_lnx_ckd_cptr()` - Free Linux cooked capture headers

## Troubleshooting

**Permission denied errors:**
```bash
# Run with sudo
sudo ./netdragon -i eth0 complete
```

**Interface not found:**
```bash
# List available interfaces first
sudo ./netdragon --list-interfaces
```

**No packets captured:**
- Check if the interface is up: `ip link show`
- Verify BPF filter syntax
- Ensure traffic is flowing on the interface
- Try without filters first

**Compilation errors:**
- Ensure libpcap-dev is installed
- Check GCC version (GCC 4.8+ recommended)
- Verify all source files are present

## Development

### Adding New Protocol Support

1. Create parser module in appropriate directory
2. Define header structure
3. Implement parsing function
4. Add memory free function
5. Update main.c to call new parser
6. Update makefile if needed

### Code Style
- C99 standard
- Snake_case for functions and variables
- UPPER_CASE for macros and constants
- Heap allocation for dynamic structures
- Always free allocated memory

## Performance Considerations

- Real-time packet capture can be CPU-intensive
- High traffic rates may cause packet drops
- Consider using BPF filters to reduce load
- Large payloads increase memory usage
- Parsing overhead varies by protocol complexity

## Security Notes

- Requires elevated privileges (CAP_NET_RAW or root)
- Can capture sensitive data (passwords, keys, etc.)
- Use responsibly and only on authorized networks
- Be aware of legal and ethical implications
- Consider encryption when storing captured data

## License

Completely open-source. Use this how you want to!!!!!!

## Contributing

Contributions are welcome! Please ensure:
- Code follows existing style conventions
- Memory is properly managed (no leaks)
- BPF filters are tested
- Documentation is updated

## Author
Njabulo Mthombeni

## Acknowledgments

- libpcap library developers
- TCP/IP protocol designers
- Open-source networking community

## References

- [libpcap documentation](https://www.tcpdump.org/)
- [Berkeley Packet Filter (BPF) syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html)
- [RFC 791 - Internet Protocol (IPv4)](https://tools.ietf.org/html/rfc791)
- [RFC 8200 - Internet Protocol Version 6 (IPv6)](https://tools.ietf.org/html/rfc8200)
- [RFC 793 - Transmission Control Protocol (TCP)](https://tools.ietf.org/html/rfc793)
- [RFC 768 - User Datagram Protocol (UDP)](https://tools.ietf.org/html/rfc768)
- [IEEE 802.3 - Ethernet Standard](https://standards.ieee.org/standard/802_3-2018.html)

(#By courtesy of Claude by Anthropic)
