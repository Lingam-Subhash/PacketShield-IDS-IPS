import threading
from typing import Dict, Any
from config.settings import DNS_AMPLIFICATION_THRESHOLD, DNS_AMPLIFICATION_WINDOW, DNS_PORT
from utils.time_utils import get_epoch_time

class DNSAmplificationDetector:
    def __init__(self):
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()

    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        protocol = packet_info.get("protocol")
        dst_port = packet_info.get("dst_port")
        src_ip = packet_info["src_ip"]
        now = get_epoch_time()
        if protocol != "UDP" or dst_port != DNS_PORT:
            return False
        with self.lock:
            if src_ip not in self.history:
                self.history[src_ip] = []
            self.history[src_ip].append(now)
            self.history[src_ip] = [t for t in self.history[src_ip] if now - t <= DNS_AMPLIFICATION_WINDOW]
            if len(self.history[src_ip]) >= DNS_AMPLIFICATION_THRESHOLD:
                self.history[src_ip] = []
                return True
        return False

    def detect(self, packet_info: Dict[str, Any]) -> tuple:
        is_attack = self.process_packet(packet_info)
        if is_attack:
            return True, {'attack_type': 'DNS Amplification', 'source_ip': packet_info["src_ip"]}
        return False, {}
