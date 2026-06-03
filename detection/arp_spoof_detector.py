import threading
from typing import Dict, Any
from scapy.all import ARP

class ARPSpoofDetector:
    def __init__(self):
        self.ip_mac_map: Dict[str, str] = {}
        self.alerted_ips: set = set()
        self.lock = threading.Lock()

    def process_arp_packet(self, raw_packet):
        if not raw_packet.haslayer(ARP):
            return False, None, None
        arp = raw_packet[ARP]
        ip = arp.psrc
        mac = arp.hwsrc
        with self.lock:
            if ip in self.ip_mac_map and self.ip_mac_map[ip] != mac and ip not in self.alerted_ips:
                self.alerted_ips.add(ip)
                return True, ip, mac
            else:
                self.ip_mac_map[ip] = mac
        return False, None, None

    def detect(self, packet_info=None):
        return False, {}
