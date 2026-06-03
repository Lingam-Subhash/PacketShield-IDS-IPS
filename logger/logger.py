import os
import csv
import logging
from typing import Dict, Any
from config.settings import ALERTS_LOG_FILE, TRAFFIC_DATA_FILE
from utils.time_utils import get_current_timestamp

class IDSIPSLogger:
    """
    IDSIPSLogger provides structured, thread-safe file logging for alerts and traffic metadata.
    """
    def __init__(self):
        self._setup_loggers()
        self._setup_csv()
        
    def _setup_loggers(self):
        """Initializes Python's standard logging module for human-readable threat entries."""
        os.makedirs(os.path.dirname(ALERTS_LOG_FILE), exist_ok=True)
        
        self.logger = logging.getLogger("IDS_IPS_Alerts")
        self.logger.setLevel(logging.INFO)
        
        # Clear default handlers to avoid double logging
        if self.logger.hasHandlers():
            self.logger.handlers.clear()
            
        file_handler = logging.FileHandler(ALERTS_LOG_FILE, mode="a", encoding="utf-8")
        formatter = logging.Formatter('[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
    def _setup_csv(self):
        """Prepares the traffic CSV file structure with standard headers if it doesn't exist."""
        os.makedirs(os.path.dirname(TRAFFIC_DATA_FILE), exist_ok=True)
        
        if not os.path.exists(TRAFFIC_DATA_FILE) or os.path.getsize(TRAFFIC_DATA_FILE) == 0:
            with open(TRAFFIC_DATA_FILE, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Source_IP", "Destination_IP", "Source_Port", "Destination_Port", "Protocol", "Flags", "Bytes"])
                
    def log_alert(self, attack_type: str, attacker_ip: str = "", action: str = "", details: Any = "", source_ip: str = ""):
        """
        Writes a standard security event alert entry to alerts.log.
        Supports both stubs and primary orchestrator parameters.
        """
        ip = attacker_ip or source_ip
        details_str = str(details)
        log_entry = f"Attack: {attack_type} | Source IP: {ip} | Action: {action} | Details: {details_str}"
        self.logger.info(log_entry)
        
    def log_traffic(self, packet_info: Dict[str, Any]):
        """
        Appends packet metadata record into traffic_data.csv for forensic tracking.
        """
        try:
            timestamp = get_current_timestamp()
            with open(TRAFFIC_DATA_FILE, mode="a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp,
                    packet_info.get("src_ip", "0.0.0.0"),
                    packet_info.get("dst_ip", "0.0.0.0"),
                    packet_info.get("src_port", 0),
                    packet_info.get("dst_port", 0),
                    packet_info.get("protocol", "UNKNOWN"),
                    packet_info.get("tcp_flags", ""),
                    packet_info.get("size", 0)
                ])
        except Exception:
            # Silently handle locking issues so it doesn't crash packet flows
            pass

# Class alias for backward compatibility with stubs
IDSLogger = IDSIPSLogger