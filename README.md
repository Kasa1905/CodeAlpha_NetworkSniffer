# Task 1: Basic Network Sniffer

## Overview
A comprehensive Python program that captures and analyzes network traffic packets in real-time.

## Features
- **Packet Capture**: Captures raw network packets using socket programming
- **Packet Analysis**: Parses and displays packet structure and content
- **Protocol Support**:
  - IPv4 packets with source/destination IP addresses
  - TCP packets with port numbers, flags, and sequence numbers
  - UDP packets with port information
  - ICMP packets with type and code information
- **Payload Display**: Shows packet payloads with support for both text and hex formats
- **Cross-platform**: Supports both Linux and macOS systems

## Requirements
- Python 3.6+
- Elevated privileges (sudo) to run raw socket operations
- Linux or macOS operating system

## Usage

### Basic Usage (Capture unlimited packets)
```bash
sudo python3 packet_sniffer.py
```

### Capture Specific Number of Packets
```bash
sudo python3 packet_sniffer.py -c 10
```
This will capture exactly 10 packets and then exit.

### With Shorthand
```bash
sudo python3 packet_sniffer.py --count 50
```

## Output Example
```
======================================================================
[PACKET #1]
======================================================================
IPv4 Packet:
  Source IP: 192.168.1.100
  Destination IP: 8.8.8.8
  Protocol: 6

TCP Packet:
  Source Port: 54321
  Destination Port: 443
  Sequence: 1234567890
  Acknowledgment: 9876543210
  Flags: SYN, ACK

  Payload (256 bytes):
  [ASCII or hex representation of payload]
```

## How It Works

1. **Socket Creation**: Creates a raw socket at the network layer to intercept all traffic
2. **Packet Reception**: Receives raw bytes from the network interface
3. **Packet Parsing**: Extracts protocol headers and interprets the data
4. **Display**: Presents information in a human-readable format

## Learning Outcomes
- Understanding of network protocols (IPv4, TCP, UDP, ICMP)
- Socket programming and raw packet handling
- Binary data parsing and interpretation
- Network traffic analysis fundamentals
- Implementation of packet dissection

## Important Notes
- **Requires Root Access**: Raw socket operations require elevated privileges
- **Performance**: Capturing high-volume traffic may impact system performance
- **Network Interface**: Sniffs on the default network interface
- **Portability**: macOS and Linux implementations differ slightly

## Future Enhancements
- DNS packet parsing
- HTTP packet payload extraction
- Packet filtering based on IP/port
- Export to PCAP format
- Graphical visualization of network flows
- Real-time statistics and graphs

## Security Considerations
- Only use this tool on networks you own or have permission to monitor
- Capturing network traffic without authorization is illegal
- Sensitive data (passwords, personal information) may be visible
- Use for educational and authorized security testing only

## References
- Socket Programming: https://docs.python.org/3/library/socket.html
- Network Protocols: https://en.wikipedia.org/wiki/Internet_protocol_suite
- Packet Structure: https://en.wikipedia.org/wiki/Network_packet
