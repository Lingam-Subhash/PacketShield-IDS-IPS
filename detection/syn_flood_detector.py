import threading
import time
from typing import Dict, Any
from config.settings import SYN_FLOOD_THRESHOLD, SYN_FLOOD_WINDOW

class SynFloodDetector:
    def __init__(self):
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()
        self.threshold = SYN_FLOOD_THRESHOLD
        self.window = SYN_FLOOD_WINDOW

    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        try:
            src_ip = packet_info.get("src_ip")
            protocol = packet_info.get("protocol")
            flags = packet_info.get("tcp_flags", "")
            if not src_ip or protocol != "TCP":
                return False
            # SYN flood: SYN flag is set, ACK flag is not set
            if "S" not in flags or "A" in flags:
                return False

            now = time.time()
            with self.lock:
                if src_ip not in self.history:
                    self.history[src_ip] = []
                self.history[src_ip].append(now)
                cutoff = now - self.window
                self.history[src_ip] = [t for t in self.history[src_ip] if t >= cutoff]
                if len(self.history[src_ip]) >= self.threshold:
                    self.history[src_ip] = []
                    return True
            return False
        except Exception as e:
            print(f"[SYNDetector ERROR] {e}")
            return False

    def detect(self, packet_info):
        is_attack = self.process_packet(packet_info)
        if is_attack:
            return True, {"attack_type": "SYN Flood", "source_ip": packet_info.get("src_ip")}
        return False, {}
