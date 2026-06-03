import threading
from typing import Dict, Any
from config.settings import UDP_FLOOD_THRESHOLD, UDP_FLOOD_WINDOW
from utils.time_utils import get_epoch_time

class UDPFloodDetector:
    """
    Detects UDP flood attacks by counting UDP packets.
    """
    def __init__(self):
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()

    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        protocol = packet_info.get("protocol")
        src_ip = packet_info["src_ip"]
        now = get_epoch_time()

        if protocol != "UDP":
            return False

        with self.lock:
            if src_ip not in self.history:
                self.history[src_ip] = []
            self.history[src_ip].append(now)
            self.history[src_ip] = [t for t in self.history[src_ip] if now - t <= UDP_FLOOD_WINDOW]
            if len(self.history[src_ip]) >= UDP_FLOOD_THRESHOLD:
                self.history[src_ip] = []
                return True
        return False

    def detect(self, packet_info: Dict[str, Any]) -> tuple:
        is_attack = self.process_packet(packet_info)
        if is_attack:
            return True, {
                'attack_type': 'UDP Flood',
                'source_ip': packet_info["src_ip"],
                'packet_count': UDP_FLOOD_THRESHOLD,
                'time_window': UDP_FLOOD_WINDOW
            }
        return False, {}