import threading
from typing import Dict, Any
try:
    from config.settings import AUTH_PORTS
except ImportError:
    AUTH_PORTS = {21, 22, 23, 3389, 5900}
from config.settings import BRUTE_FORCE_THRESHOLD, BRUTE_FORCE_WINDOW
from utils.time_utils import get_epoch_time

class BruteForceDetector:
    """
    BruteForceDetector checks for excessive connection rates targeting authentication ports (SSH, FTP, Telnet).
    """
    def __init__(self):
        # Maps source IP to a list of timestamps when connections were initiated to auth ports
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()
        
    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        """
        Assesses whether a connection represents a potential authentication brute-force attempt.
        
        :param packet_info: Extracted packet fields.
        :return: True if brute force is detected, False otherwise.
        """
        protocol = packet_info["protocol"]
        dst_port = packet_info["dst_port"]
        src_ip = packet_info["src_ip"]
        flags = packet_info.get("tcp_flags", "")
        now = get_epoch_time()
        
        # Brute force targeting ports like SSH/FTP normally occurs over TCP.
        # We look for connection requests (SYN flag set) to authentication ports.
        if protocol == "TCP" and dst_port in AUTH_PORTS:
            # We want connection initiation (SYN packet)
            if "S" in flags and "A" not in flags:
                with self.lock:
                    if src_ip not in self.history:
                        self.history[src_ip] = []
                        
                    self.history[src_ip].append(now)
                    
                    # Slide time-window
                    self.history[src_ip] = [
                        t for t in self.history[src_ip]
                        if (now - t) <= BRUTE_FORCE_WINDOW
                    ]
                    
                    # Check threshold
                    if len(self.history[src_ip]) >= BRUTE_FORCE_THRESHOLD:
                        self.history[src_ip] = []
                        return True
                        
        return False
        
    def detect(self, packet_info: Dict[str, Any]) -> tuple:
        """
        Backward compatibility wrapper mapping to process_packet().
        """
        is_attack = self.process_packet(packet_info)
        if is_attack:
            return True, {
                'attack_type': 'Brute Force',
                'source_ip': packet_info["src_ip"],
                'ports_targeted': [packet_info["dst_port"]],
                'attempt_count': BRUTE_FORCE_THRESHOLD,
                'time_window': BRUTE_FORCE_WINDOW
            }
        return False, {}

    def get_auth_connection_count(self, src_ip: str) -> int:
        """Returns currently tracked connection count inside the sliding window targeting auth ports."""
        with self.lock:
            if src_ip not in self.history:
                return 0
            return len(self.history[src_ip])