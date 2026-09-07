import threading
import time
from collections import defaultdict
from typing import Dict, Any
from config.settings import DDoS_THRESHOLD, DDoS_WINDOW

class DDoSDetector:
    def __init__(self):
        # key = (dst_ip, dst_port) -> set of source IPs
        self.targets: Dict[tuple, set] = defaultdict(set)
        self.timestamps: Dict[tuple, float] = {}
        self.lock = threading.Lock()
        self.threshold = DDoS_THRESHOLD
        self.window = DDoS_WINDOW

    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        try:
            src_ip = packet_info.get("src_ip")
            dst_ip = packet_info.get("dst_ip")
            dst_port = packet_info.get("dst_port")
            if not src_ip or not dst_ip:
                return False

            key = (dst_ip, dst_port)
            now = time.time()
            with self.lock:
                # Add source IP to the set
                self.targets[key].add(src_ip)
                self.timestamps[key] = now

                # Remove old entries if window expired
                if now - self.timestamps[key] > self.window:
                    self.targets[key].clear()
                    self.timestamps[key] = now
                    return False

                # Check unique source count
                if len(self.targets[key]) >= self.threshold:
                    self.targets[key].clear()
                    self.timestamps[key] = now
                    print(f"[DDoS] Detected on {dst_ip}:{dst_port} from {len(self.targets[key])} sources")
                    return True
            return False
        except Exception as e:
            print(f"[DDoS ERROR] {e}")
            return False

    def detect(self, packet_info):
        is_attack = self.process_packet(packet_info)
        if is_attack:
            return True, {"attack_type": "DDoS Attack", "source_ip": "multiple"}
        return False, {}
