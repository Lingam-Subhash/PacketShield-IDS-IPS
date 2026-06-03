import os

# ==========================================
# Network IDS/IPS Configuration Settings
# ==========================================

# 1. Network Interface Setup
# Set to None for automatic scapy interface selection or loopback interfaces
INTERFACE = None

# 2. Storage & Directory Configs
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STORAGE_DIR = os.path.join(BASE_DIR, "storage")

# Ensure storage directory exists
if not os.path.exists(STORAGE_DIR):
    os.makedirs(STORAGE_DIR, exist_ok=True)

BLOCKED_IPS_FILE = os.path.join(STORAGE_DIR, "blocked_ips.txt")
ALERTS_LOG_FILE = os.path.join(STORAGE_DIR, "alerts.log")
TRAFFIC_DATA_FILE = os.path.join(STORAGE_DIR, "traffic_data.csv")

# 3. Detection Engine Thresholds & Window Parameters
# PORT SCAN: Number of unique ports scanned by a single IP within a set sliding window (in seconds)
PORT_SCAN_THRESHOLD = 20
PORT_SCAN_WINDOW = 5.0

# SYN FLOOD: Number of TCP SYN packets received from a single IP within a sliding window
SYN_FLOOD_THRESHOLD = 100
SYN_FLOOD_WINDOW = 5.0

# ICMP FLOOD: Number of ICMP Echo Request packets received from a single IP within a sliding window
ICMP_FLOOD_THRESHOLD = 10
ICMP_FLOOD_WINDOW = 5.0

# BRUTE FORCE: Number of rapid connections made to standard authentication ports (21 FTP, 22 SSH, 23 Telnet)
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_WINDOW = 10.0
AUTH_PORTS = {21, 22, 23}

# 4. IPS Prevention Engine Settings
# Block duration in seconds. After this duration, the IP is automatically unblocked (0 for permanent block)
BLOCK_TIME = 300

# Perform active firewall blocks (simulated by default to avoid permission denial crashes, 
# but can execute local shell commands if set to True)
EXECUTE_SYSTEM_BLOCK = False

# ACK Flood detection
ACK_FLOOD_THRESHOLD = 100
ACK_FLOOD_WINDOW = 5.0

# UDP Flood detection
UDP_FLOOD_THRESHOLD = 10
UDP_FLOOD_WINDOW = 5.0

# DNS Amplification detection
DNS_AMPLIFICATION_THRESHOLD = 50
DNS_AMPLIFICATION_WINDOW = 5.0
DNS_PORT = 53

# ARP Spoofing detection (for Packet Sniffing / MITM)
ARP_SPOOF_CHECK_INTERVAL = 10

# DDoS detection
DDoS_THRESHOLD = 10        # number of distinct source IPs
DDoS_WINDOW = 10.0         # seconds