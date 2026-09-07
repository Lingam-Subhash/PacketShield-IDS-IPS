import threading
from typing import Dict, Set, Any
from config.settings import PORT_SCAN_THRESHOLD, PORT_SCAN_WINDOW
from utils.time_utils import get_epoch_time

class PortScanDetector:
    """
    PortScanDetector analyzes packet metadata in real-time to detect port scanning behavior.
    
    Logic:
    - Tracks destination ports accessed by each unique source IP.
    - Uses a sliding window algorithm to automatically purge connection timestamps older than PORT_SCAN_WINDOW.
    - If the number of unique destination ports targeted by a single source IP exceeds PORT_SCAN_THRESHOLD 
      within the window, a port scanning threat is detected and reported.
    """
    def __init__(self):
        # Maps source IP to list of tuples: (port, timestamp)
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()
        
    def process_packet(self, packet_info: Dict[str, Any]) -> bool:
        """
        Processes a packet and checks if it constitutes a Port Scan attack.
        
        :param packet_info: Parsed packet metadata dictionary.
        :return: True if port scan is detected, False otherwise.
        """
        src_ip = packet_info["src_ip"]
        dst_port = packet_info["dst_port"]
        protocol = packet_info["protocol"]
        now = get_epoch_time()
        
        # ICMP packets do not use ports in a standard way; skip port scan evaluation for non-port protocols
        if protocol not in ("TCP", "UDP"):
            return False
            
        with self.lock:
            # Initialize history for new IP
            if src_ip not in self.history:
                self.history[src_ip] = []
                
            # Add current attempt: (destination port, timestamp)
            self.history[src_ip].append((dst_port, now))
            
            # Slide window: remove historical entries older than the threshold window
            self.history[src_ip] = [
                entry for entry in self.history[src_ip] 
                if (now - entry[1]) <= PORT_SCAN_WINDOW
            ]
            
            # Extract set of unique destination ports targeted inside the sliding window
            unique_ports = {entry[0] for entry in self.history[src_ip]}
            
            # Check if threshold crossed
            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                # Clear history for this IP upon detection to prevent redundant, runaway alerts 
                # before the IPS has blocked it.
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
                'attack_type': 'Port Scan',
                'source_ip': packet_info["src_ip"],
                'ports_scanned': PORT_SCAN_THRESHOLD,
                'time_window': PORT_SCAN_WINDOW
            }
        return False, {}

    def get_unique_port_count(self, src_ip: str) -> int:
        """Returns number of currently tracked unique ports targeted by an IP."""
        with self.lock:
            if src_ip not in self.history:
                return 0
            return len({entry[0] for entry in self.history[src_ip]})