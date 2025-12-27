# CodeAlpha_NetworkSniffer Setup Guide

## 🚀 Quick Start

### 1. Environment Setup

```bash
# Navigate to project directory
cd CodeAlpha_NetworkSniffer

# Activate virtual environment
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation
pip list
```

### 2. Run the Application

```bash
# Basic usage (capture unlimited packets)
sudo python3 packet_sniffer.py

# Capture specific number of packets
sudo python3 packet_sniffer.py -c 50

# Exit: Press Ctrl+C
```

### 3. Troubleshooting

| Issue | Solution |
|-------|----------|
| Permission denied | Use `sudo` before python3 |
| scapy not found | Run `pip install scapy>=2.4.5` |
| No packets captured | Check internet connection |

---

## 📋 For Video Recording

### Script Points (5-8 minutes):
1. **Intro** (0:00-0:30): Overview of packet sniffing
2. **Structure** (0:30-1:00): Show project files
3. **Code Walkthrough** (1:00-3:00): Explain PacketSniffer class
4. **Environment** (3:00-4:00): Virtual env and pip install
5. **Demo** (4:00-7:00): Run sniffer, capture packets
6. **Explanation** (7:00-7:30): Protocols and applications
7. **Conclusion** (7:30-8:00): Summary

### Recording Tips:
- Font size: 14pt minimum
- Terminal width: Full screen
- Speak slowly when explaining protocols
- Pause 2 seconds between sections
- Highlight key lines with cursor

### File Structure to Show:
```
CodeAlpha_NetworkSniffer/
├── .venv/                  (Explain: Python environment)
├── packet_sniffer.py       (Explain: Main program)
├── README.md              (Explain: Documentation)
└── requirements.txt       (Explain: Dependencies)
```

---

## 📚 Key Concepts to Explain

### PacketSniffer Class
```python
class PacketSniffer:
    def sniff(self):        # Capture packets
    def _parse_packet(self): # Parse packet data
```

### Protocols Covered
- **IPv4**: IP addresses, headers
- **TCP**: Ports, flags, connections
- **UDP**: Datagram structure
- **ICMP**: Ping, error messages

### Real-World Applications
- Network troubleshooting
- Security monitoring
- Traffic analysis
- Protocol learning

---

## ✅ Repo Checklist

- [x] Virtual environment configured
- [x] Dependencies listed in requirements.txt
- [x] Code fully commented
- [x] README provided
- [x] Error handling implemented
- [x] Works on macOS and Linux

**Ready for Video Recording** ✅
