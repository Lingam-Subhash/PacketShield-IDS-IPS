import threading
import time
from typing import Dict, Any
from config.settings import ACK_FLOOD_THRESHOLD, ACK_FLOOD_WINDOW

class ACKFloodDetector:
    def __init__(self):
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()
        self.threshold = ACK_FLOOD_THRESHOLD
        self.window = ACK_FLOOD_WINDOW

    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        try:
            src_ip = packet_info.get("src_ip")
            protocol = packet_info.get("protocol")
            flags = packet_info.get("tcp_flags", "")
            if not src_ip or protocol != "TCP":
                return False
            # ACK flood: ACK flag is set, SYN flag is not set
            if "A" not in flags or "S" in flags:
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
            print(f"[ACKDetector ERROR] {e}")
            return False

    def detect(self, packet_info):
        is_attack = self.process_packet(packet_info)
        if is_attack:
            return True, {"attack_type": "ACK Flood", "source_ip": packet_info.get("src_ip")}
        return False, {}
