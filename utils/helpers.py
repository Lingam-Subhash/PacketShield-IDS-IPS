import re
import socket
from datetime import datetime

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class DummyColorama:
        def __getattr__(self, name):
            return ""
    Fore = DummyColorama()
    Style = DummyColorama()

def center_line(text: str, width: int = 72) -> str:
    """Center a line of text within a given width."""
    text = str(text)
    if len(text) >= width:
        return text
    pad = (width - len(text)) // 2
    return " " * pad + text

def log_info(msg: str):
    """Prints standard info message in green."""
    print(f"{Fore.GREEN}[INFO] {msg}{Style.RESET_ALL}")

def log_warning(msg: str):
    """Prints warning message in yellow."""
    print(f"{Fore.YELLOW}[WARN] {msg}{Style.RESET_ALL}")

def log_alert(msg: str):
    """Prints danger/threat alert message in red with bright style."""
    print(f"{Fore.RED}{Style.BRIGHT}[ALERT] {msg}{Style.RESET_ALL}")

def is_valid_ip(ip: str) -> bool:
    """
    Checks if a string is a valid IPv4 or IPv6 address.
    """
    ipv4_pattern = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    if re.match(ipv4_pattern, ip):
        return True

    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except socket.error:
        pass

    return False

def validate_ip(ip: str) -> bool:
    return is_valid_ip(ip)

def get_protocol_name(proto_num: int) -> str:
    proto_map = {
        1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
        41: "IPv6-Route", 47: "GRE", 50: "ESP", 51: "AH",
        58: "IPv6-ICMP", 89: "OSPF"
    }
    return proto_map.get(proto_num, f"PROTO-{proto_num}")