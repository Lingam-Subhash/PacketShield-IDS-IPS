from typing import Dict, Any, Optional
from scapy.all import Packet, IP, TCP, UDP, ICMP
from utils.helpers import get_protocol_name, log_warning
from utils.time_utils import get_epoch_time

class PacketAnalyzer:
    """
    PacketAnalyzer receives raw Scapy Packet objects or pre-parsed dict payloads,
    validates them, and extracts standard structured dictionaries.
    """
    @staticmethod
    def analyze(packet: Any) -> Optional[Dict[str, Any]]:
        """
        Parses a raw network packet and extracts structured header details.
        Handles both raw Scapy Packet objects and pre-parsed mock dictionaries.
        
        :param packet: Scapy packet object or dict representation.
        :return: Dict containing extracted header data, or None if packet is invalid.
        """
        # If the packet is already a pre-parsed dictionary (from UDP fallback sniffer),
        # return it directly, bypass the Scapy extraction.
        if isinstance(packet, dict):
            return packet

        # Ensure packet has an IP layer (IPv4 or IPv6)
        if not packet.haslayer(IP):
            return None

        try:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto_num = ip_layer.proto
            protocol = get_protocol_name(proto_num)
            
            # Default empty values
            src_port = 0
            dst_port = 0
            tcp_flags = ""
            
            # Layer parsing based on transport layer protocols
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                src_port = int(tcp_layer.sport)
                dst_port = int(tcp_layer.dport)
                tcp_flags = str(tcp_layer.flags) # Returns flags e.g. "S", "SA"
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                src_port = int(udp_layer.sport)
                dst_port = int(udp_layer.dport)
                
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                src_port = int(icmp_layer.type) # e.g. 8 for Echo Request
                dst_port = int(icmp_layer.code) # e.g. 0
                
            packet_size = len(packet)
            timestamp = get_epoch_time()
            
            return {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "tcp_flags": tcp_flags,
                "size": packet_size,
                "timestamp": timestamp
            }
            
        except Exception as e:
            log_warning(f"Failed to analyze packet layers: {str(e)}")
            return None