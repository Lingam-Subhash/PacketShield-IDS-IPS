import threading
import time
from typing import Dict, Any
from config.settings import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW, AUTH_PORTS

class BruteForceDetector:
    def __init__(self):
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()
        self.threshold = BRUTE_FORCE_THRESHOLD
        self.window = BRUTE_FORCE_WINDOW

    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        try:
            src_ip = packet_info.get("src_ip")
            protocol = packet_info.get("protocol")
            dst_port = packet_info.get("dst_port")
            flags = packet_info.get("tcp_flags", "")
            if not src_ip or protocol != "TCP":
                return False
            if dst_port not in AUTH_PORTS:
                return False
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
                    print(f"[BruteForce] Detected from {src_ip}")   # debug
                    return True
            return False
        except Exception as e:
            print(f"[BruteForce ERROR] {e}")
            return False

    def detect(self, packet_info):
        is_attack = self.process_packet(packet_info)
        if is_attack:
            return True, {"attack_type": "Brute Force", "source_ip": packet_info.get("src_ip")}
        return False, {}
