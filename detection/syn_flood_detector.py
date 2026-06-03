import threading
from typing import Dict, Any
from config.settings import SYN_FLOOD_THRESHOLD, SYN_FLOOD_WINDOW
from utils.time_utils import get_epoch_time

class SynFloodDetector:
    """
    SynFloodDetector inspects TCP flags to detect potential SYN flood DDoS attacks.
    """
    def __init__(self):
        # Maps source IP to a list of timestamps when SYN packets were received
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()
        
    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        """
        Evaluates a packet and determines if it triggers a SYN Flood alert.
        
        :param packet_info: Extracted packet details.
        :return: True if SYN Flood attack is detected, False otherwise.
        """
        protocol = packet_info["protocol"]
        flags = packet_info.get("tcp_flags", "")
        src_ip = packet_info["src_ip"]
        now = get_epoch_time()
        
        # Only evaluate TCP packets
        if protocol != "TCP":
            return False
            
        # A pure SYN connection request has the SYN ("S") flag set and does not have the ACK ("A") flag
        if "S" in flags and "A" not in flags:
            with self.lock:
                if src_ip not in self.history:
                    self.history[src_ip] = []
                    
                # Store connection attempt timestamp
                self.history[src_ip].append(now)
                
                # Slide time-window: prune attempts older than the configuration threshold
                self.history[src_ip] = [
                    t for t in self.history[src_ip]
                    if (now - t) <= SYN_FLOOD_WINDOW
                ]
                
                # Check threshold
                if len(self.history[src_ip]) >= SYN_FLOOD_THRESHOLD:
                    # Clear history to avoid continuous repetitive firing of alerts
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
                'attack_type': 'SYN Flood',
                'source_ip': packet_info["src_ip"],
                'packet_count': SYN_FLOOD_THRESHOLD,
                'time_window': SYN_FLOOD_WINDOW
            }
        return False, {}

    def get_syn_count(self, src_ip: str) -> int:
        """Returns current tracked SYN count within the current sliding window for an IP."""
        with self.lock:
            if src_ip not in self.history:
                return 0
            return len(self.history[src_ip])