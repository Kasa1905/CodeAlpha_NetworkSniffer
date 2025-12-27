"""
Task 1: Basic Network Sniffer
A Python program to capture and analyze network traffic packets.
This sniffer demonstrates understanding of network protocols and data flow.
"""

import socket
import textwrap
import struct
import sys
import signal


class PacketSniffer:
    def __init__(self, packet_count=0):
        """
        Initialize the packet sniffer.
        
        Args:
            packet_count: Number of packets to capture (0 = unlimited)
        """
        self.packet_count = packet_count
        self.packets_captured = 0
    
    def sniff(self):
        """Capture network packets"""
        try:
            # Create a raw socket that receives all packets
            if sys.platform == 'darwin':  # macOS
                # macOS raw sockets do not support SIO_RCVALL; this captures inbound packets only
                conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                conn.bind((self._get_local_ip(), 0))
                conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                print("[!] macOS capture is limited to inbound IPv4 packets (SIO_RCVALL unsupported)")
            else:
                # Linux approach
                conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            
            print("[*] Starting Packet Sniffer...")
            print(f"[*] Capturing packets (Press Ctrl+C to stop)...\n")
            
            while True:
                if self.packet_count != 0 and self.packets_captured >= self.packet_count:
                    break
                
                raw_buffer, addr = conn.recvfrom(65535)
                self.packets_captured += 1
                
                print(f"\n{'='*70}")
                print(f"[PACKET #{self.packets_captured}]")
                print(f"{'='*70}")
                
                self._parse_packet(raw_buffer)
                
        except PermissionError:
            print("[!] Error: This script requires elevated privileges (run with sudo)")
            sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n[*] Capture stopped. Total packets captured: {self.packets_captured}")
            sys.exit(0)
        except Exception as e:
            print(f"[!] Error: {str(e)}")
            sys.exit(1)
        finally:
            if 'conn' in locals():
                try:
                    conn.close()
                except:
                    pass
    
    def _get_local_ip(self):
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _parse_packet(self, raw_buffer):
        """Parse and display packet information"""
        try:
            ipv4_packet = IPv4Packet(raw_buffer)
            print(f"IPv4 Packet:")
            print(f"  Source IP: {ipv4_packet.src}")
            print(f"  Destination IP: {ipv4_packet.dest}")
            print(f"  Protocol: {ipv4_packet.proto}")
            
            # Handle ICMP
            if ipv4_packet.proto == 1:
                print(f"\nICMP Packet:")
                icmp_packet = ICMPPacket(ipv4_packet.data)
                print(f"  Type: {icmp_packet.type}")
                print(f"  Code: {icmp_packet.code}")
                print(f"  Checksum: {icmp_packet.checksum}")
            
            # Handle TCP
            elif ipv4_packet.proto == 6:
                print(f"\nTCP Packet:")
                tcp_packet = TCPPacket(ipv4_packet.data)
                print(f"  Source Port: {tcp_packet.src_port}")
                print(f"  Destination Port: {tcp_packet.dest_port}")
                print(f"  Sequence: {tcp_packet.sequence}")
                print(f"  Acknowledgment: {tcp_packet.acknowledgment}")
                print(f"  Flags: {self._format_flags(tcp_packet.flags)}")
                
                if len(tcp_packet.data) > 0:
                    print(f"\n  Payload ({len(tcp_packet.data)} bytes):")
                    print(self._format_payload(tcp_packet.data))
            
            # Handle UDP
            elif ipv4_packet.proto == 17:
                print(f"\nUDP Packet:")
                udp_packet = UDPPacket(ipv4_packet.data)
                print(f"  Source Port: {udp_packet.src_port}")
                print(f"  Destination Port: {udp_packet.dest_port}")
                print(f"  Length: {udp_packet.length}")
                
                if len(udp_packet.data) > 0:
                    print(f"\n  Payload ({len(udp_packet.data)} bytes):")
                    print(self._format_payload(udp_packet.data))
        
        except Exception as e:
            print(f"[!] Error parsing packet: {str(e)}")
    
    def _format_flags(self, flags):
        """Format TCP flags in readable form"""
        flag_names = []
        if flags & 0x01:  # FIN
            flag_names.append("FIN")
        if flags & 0x02:  # SYN
            flag_names.append("SYN")
        if flags & 0x04:  # RST
            flag_names.append("RST")
        if flags & 0x08:  # PSH
            flag_names.append("PSH")
        if flags & 0x10:  # ACK
            flag_names.append("ACK")
        if flags & 0x20:  # URG
            flag_names.append("URG")
        return ", ".join(flag_names) if flag_names else "None"
    
    def _format_payload(self, data, length=80):
        """Format packet payload for display"""
        length = min(length, len(data))
        if all(32 <= byte < 127 for byte in data[:length]):
            return textwrap.fill(data[:length].decode("utf-8", errors="ignore"), width=80)
        else:
            return textwrap.fill(" ".join(f"{byte:02x}" for byte in data[:length]), width=80)


class IPv4Packet:
    """Parse IPv4 packets"""
    def __init__(self, buf):
        version_header_length = buf[0]
        self.version = version_header_length >> 4
        self.header_length = (version_header_length & 15) * 4
        self.ttl = buf[8]
        self.proto = buf[9]
        self.src = self._format_ipv4_address(buf[12:16])
        self.dest = self._format_ipv4_address(buf[16:20])
        self.data = buf[self.header_length:]
    
    @staticmethod
    def _format_ipv4_address(bytes_addr):
        """Format IPv4 address"""
        return ".".join(map(str, bytes_addr))


class ICMPPacket:
    """Parse ICMP packets"""
    def __init__(self, buf):
        self.type = buf[0]
        self.code = buf[1]
        self.checksum = struct.unpack(">H", buf[2:4])[0]
        self.data = buf[4:]


class TCPPacket:
    """Parse TCP packets"""
    def __init__(self, buf):
        (self.src_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(">HHIIH", buf[0:14])
        self.offset = (offset_reserved_flags >> 12) * 4
        self.flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack = (offset_reserved_flags & 16) >> 4
        self.flag_psh = (offset_reserved_flags & 8) >> 3
        self.flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn = (offset_reserved_flags & 2) >> 1
        self.flag_fin = offset_reserved_flags & 1
        self.flags = offset_reserved_flags & 0x3F
        self.data = buf[self.offset:]


class UDPPacket:
    """Parse UDP packets"""
    def __init__(self, buf):
        (self.src_port, self.dest_port, self.length) = struct.unpack(">HHH", buf[0:6])
        self.data = buf[8:]


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Basic Network Packet Sniffer")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (default: 0 = unlimited)")
    args = parser.parse_args()
    
    sniffer = PacketSniffer(args.count)
    sniffer.sniff()


if __name__ == "__main__":
    main()
