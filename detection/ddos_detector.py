# detection/ddos_detector.py
import threading
from collections import defaultdict
from utils.time_utils import get_epoch_time
from config.settings import DDoS_THRESHOLD, DDoS_WINDOW

class DDoSDetector:
    """
    Basic DDoS detection: multiple source IPs targeting the same destination
    within a time window.
    """
    def __init__(self):
        self.targets = defaultdict(list)
        self.lock = threading.Lock()

    def process_packet(self, packet_info):
        src_ip = packet_info.get("src_ip")
        dst_ip = packet_info.get("dst_ip")
        dst_port = packet_info.get("dst_port")
        now = get_epoch_time()
        if not src_ip or not dst_ip:
            return False

        key = (dst_ip, dst_port)
        with self.lock:
            self.targets[key].append((src_ip, now))
            self.targets[key] = [(ip, ts) for (ip, ts) in self.targets[key] if now - ts <= DDoS_WINDOW]
            unique_sources = {ip for ip, _ in self.targets[key]}
            if len(unique_sources) >= DDoS_THRESHOLD:
                self.targets[key] = []
                return True
        return False

    def detect(self, packet_info):
        is_attack = self.process_packet(packet_info)
        if is_attack:
            return True, {
                'attack_type': 'DDoS Attack',
                'source_ip': 'multiple',
                'target': f"{packet_info['dst_ip']}:{packet_info['dst_port']}",
                'unique_sources': DDoS_THRESHOLD,
                'time_window': DDoS_WINDOW
            }
        return False, {}