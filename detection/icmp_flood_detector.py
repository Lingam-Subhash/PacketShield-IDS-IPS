import threading
from typing import Dict, Any
from config.settings import ICMP_FLOOD_THRESHOLD, ICMP_FLOOD_WINDOW
from utils.time_utils import get_epoch_time

class ICMPFloodDetector:
    """
    ICMPFloodDetector identifies Ping Flood attacks by tracking the arrival rate of ICMP Echo Requests.
    """
    def __init__(self):
        # Maps source IP to a list of ICMP packet arrival epoch timestamps
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()
        
    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        """
        Processes a packet to evaluate whether it represents a ping flood attack.
        
        :param packet_info: Parsed packet payload.
        :return: True if ICMP Flood is detected, False otherwise.
        """
        protocol = packet_info["protocol"]
        src_ip = packet_info["src_ip"]
        icmp_type = packet_info["src_port"]  # The type was stored in src_port by PacketAnalyzer
        now = get_epoch_time()
        
        # We only look for ICMP packets
        if protocol != "ICMP":
            return False
            
        # Standard Ping request is type 8 (Echo Request) or type 128 (ICMPv6 Echo Request)
        if icmp_type in (8, 128):
            with self.lock:
                if src_ip not in self.history:
                    self.history[src_ip] = []
                    
                # Store ping arrival timestamp
                self.history[src_ip].append(now)
                
                # Slide window
                self.history[src_ip] = [
                    t for t in self.history[src_ip]
                    if (now - t) <= ICMP_FLOOD_WINDOW
                ]
                
                # Check threshold
                if len(self.history[src_ip]) >= ICMP_FLOOD_THRESHOLD:
                    # Flush history for this IP
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
                'attack_type': 'ICMP Flood',
                'source_ip': packet_info["src_ip"],
                'packet_count': ICMP_FLOOD_THRESHOLD,
                'time_window': ICMP_FLOOD_WINDOW
            }
        return False, {}

    def get_icmp_count(self, src_ip: str) -> int:
        """Returns currently tracked ICMP count within the sliding window."""
        with self.lock:
            if src_ip not in self.history:
                return 0
            return len(self.history[src_ip])