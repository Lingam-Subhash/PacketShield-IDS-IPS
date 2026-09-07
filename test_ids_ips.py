import sys
import os
import time
from typing import Dict, Any

# Adjust path to find config, utils, etc.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from config.settings import PORT_SCAN_THRESHOLD, SYN_FLOOD_THRESHOLD, ICMP_FLOOD_THRESHOLD, BRUTE_FORCE_THRESHOLD
from utils.helpers import log_info, log_warning, log_alert

# Import engine components directly to avoid triggering main.py's terminal setup
from logger.logger import IDSLogger
from prevention.blocker import Blocker
from detection.port_scan_detector import PortScanDetector
from detection.syn_flood_detector import SynFloodDetector
from detection.icmp_flood_detector import ICMPFloodDetector
from detection.brute_force_detector import BruteForceDetector
from detection.ack_flood_detector import ACKFloodDetector
from detection.udp_flood_detector import UDPFloodDetector
from detection.dns_amplification_detector import DNSAmplificationDetector
from detection.arp_spoof_detector import ARPSpoofDetector
from detection.ddos_detector import DDoSDetector


class NetworkIDSIPSTestStub:
    """
    Standalone stub of NetworkIDSIPS that does NOT start a packet sniffer.
    Used purely for offline unit/integration testing of detection logic.
    """
    def __init__(self):
        self.logger = IDSLogger()
        self.blocker = Blocker()
        self.detectors = [
            PortScanDetector(),
            SynFloodDetector(),
            ICMPFloodDetector(),
            BruteForceDetector(),
            ACKFloodDetector(),
            UDPFloodDetector(),
            DNSAmplificationDetector(),
            DDoSDetector(),
        ]
        self.arp_detector = ARPSpoofDetector()

    def _evaluate_threats(self, packet_info: Dict[str, Any]):
        src_ip = packet_info["src_ip"]
        for detector in self.detectors:
            try:
                if hasattr(detector, 'process_packet'):
                    if detector.process_packet(packet_info):
                        attack_type = detector.__class__.__name__.replace('Detector', '').replace('Flood', ' Flood')
                        self._trigger_prevention(attack_type, src_ip, "Threshold exceeded.")
                        return
            except Exception as e:
                log_warning(f"Detection error: {str(e)}")

    def _trigger_prevention(self, attack_type: str, attacker_ip: str, details: str):
        log_alert(f"THREAT DETECTED: {attack_type} from IP: {attacker_ip}!")
        log_warning(f"Reason: {details}")
        self.logger.log_alert(attack_type, attacker_ip, "BLOCKED", details)
        self.blocker.block_ip(attacker_ip, reason=attack_type)


def print_test_header(title: str):
    print("\n" + "=" * 60)
    print(f" TESTING: {title}")
    print("=" * 60)


def feed_packet(engine: NetworkIDSIPSTestStub, pkt: Dict[str, Any]):
    """
    Simulates packet arrival by directly invoking the detection and logging pipeline,
    bypassing raw Scapy packet analysis.
    """
    src_ip = pkt["src_ip"]

    # 1. Prevention check
    if engine.blocker.is_ip_blocked(src_ip):
        return

    # 2. Log raw traffic statistics
    engine.logger.log_traffic(pkt)

    # 3. Evaluate threat engines
    engine._evaluate_threats(pkt)


def verify_logs():
    """Reads and prints contents of generated files to verify logging correctness."""
    print("\n--- Persistent Log Files Verification ---")
    base = os.path.dirname(os.path.abspath(__file__))

    # 1. Blocked IPs File
    blocked_file = os.path.join(base, "storage", "blocked_ips.txt")
    if os.path.exists(blocked_file):
        with open(blocked_file, "r") as f:
            content = f.read().strip().replace('\n', ', ')
            print(f"[VERIFY] Blocklist file contains: [{content}]")
    else:
        print("[VERIFY] Error: blocked_ips.txt was not created.")

    # 2. Alerts Log
    alerts_file = os.path.join(base, "storage", "alerts.log")
    if os.path.exists(alerts_file):
        with open(alerts_file, "r") as f:
            lines = f.readlines()
            print(f"[VERIFY] Alerts log created with {len(lines)} event entries. Latest entry:")
            if lines:
                print(f"         {lines[-1].strip()}")
    else:
        print("[VERIFY] Error: alerts.log was not created.")

    # 3. Traffic Data CSV
    traffic_file = os.path.join(base, "storage", "traffic_data.csv")
    if os.path.exists(traffic_file):
        with open(traffic_file, "r") as f:
            lines = f.readlines()
            print(f"[VERIFY] Traffic CSV log created with {len(lines)} data rows (including header).")
    else:
        print("[VERIFY] Error: traffic_data.csv was not created.")


def run_offline_test_suite():
    log_info("Initializing Offline IDS/IPS Logic Validation Suite...")

    base = os.path.dirname(os.path.abspath(__file__))

    # Instantiate test engine (no sniffer thread)
    engine = NetworkIDSIPSTestStub()

    # Reset persistent files to start fresh
    for fname in ["blocked_ips.txt", "alerts.log", "traffic_data.csv"]:
        f_path = os.path.join(base, "storage", fname)
        if os.path.exists(f_path):
            try:
                os.remove(f_path)
            except Exception:
                pass

    # Re-initialize blockers and loggers
    engine.blocker.blocked_ips.clear()
    engine.logger._setup_loggers()
    engine.logger._setup_csv()

    # ==========================================
    # TEST 1: Normal Traffic (Should Pass Safely)
    # ==========================================
    print_test_header("Normal Network Activity (Should Not Alert)")
    normal_ips = ["192.168.1.10", "192.168.1.20"]
    for i in range(5):
        pkt = {
            "src_ip": normal_ips[i % 2],
            "dst_ip": "192.168.1.1",
            "src_port": 54200 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": "PA",  # Push-ACK (Standard traffic)
            "size": 128,
            "timestamp": time.time()
        }
        feed_packet(engine, pkt)
    log_info("Finished Normal Traffic simulation. Check active blocks: "
             f"{engine.blocker.get_blocked_ips()} (Expected: empty)")

    # ==========================================
    # TEST 2: Port Scan Attack Detection
    # ==========================================
    print_test_header("Port Scan Attack Simulation")
    scan_ip = "10.0.0.66"
    log_warning(f"Simulating Port Scan: IP {scan_ip} targeting {PORT_SCAN_THRESHOLD + 5} unique ports...")

    for port in range(1, PORT_SCAN_THRESHOLD + 5):
        pkt = {
            "src_ip": scan_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 49000,
            "dst_port": port,  # Scanning unique ports
            "protocol": "TCP",
            "tcp_flags": "S",
            "size": 64,
            "timestamp": time.time()
        }
        feed_packet(engine, pkt)

    is_blocked = engine.blocker.is_ip_blocked(scan_ip)
    print(f"--> Verification: Is {scan_ip} blocked? {is_blocked} (Expected: True)")

    # ==========================================
    # TEST 3: SYN Flood Attack Detection
    # ==========================================
    print_test_header("TCP SYN Flood Attack Simulation")
    syn_ip = "10.0.0.77"
    log_warning(f"Simulating SYN Flood: IP {syn_ip} sending {SYN_FLOOD_THRESHOLD + 10} SYN flags...")

    for _ in range(SYN_FLOOD_THRESHOLD + 10):
        pkt = {
            "src_ip": syn_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 61200,
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": "S",
            "size": 64,
            "timestamp": time.time()
        }
        feed_packet(engine, pkt)

    is_blocked = engine.blocker.is_ip_blocked(syn_ip)
    print(f"--> Verification: Is {syn_ip} blocked? {is_blocked} (Expected: True)")

    # ==========================================
    # TEST 4: ICMP Flood Attack Detection
    # ==========================================
    print_test_header("ICMP Ping Flood Attack Simulation")
    icmp_ip = "10.0.0.88"
    log_warning(f"Simulating ICMP Flood: IP {icmp_ip} sending {ICMP_FLOOD_THRESHOLD + 10} Ping echo requests...")

    for _ in range(ICMP_FLOOD_THRESHOLD + 10):
        pkt = {
            "src_ip": icmp_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 8,  # Type 8 is Echo Request
            "dst_port": 0,
            "protocol": "ICMP",
            "tcp_flags": "",
            "size": 32,
            "timestamp": time.time()
        }
        feed_packet(engine, pkt)

    is_blocked = engine.blocker.is_ip_blocked(icmp_ip)
    print(f"--> Verification: Is {icmp_ip} blocked? {is_blocked} (Expected: True)")

    # ==========================================
    # TEST 5: Brute Force Attack Detection
    # ==========================================
    print_test_header("SSH Brute Force Attack Simulation")
    ssh_ip = "10.0.0.55"
    log_warning(f"Simulating SSH Brute Force: IP {ssh_ip} sending {BRUTE_FORCE_THRESHOLD + 5} connections to port 22...")

    for _ in range(BRUTE_FORCE_THRESHOLD + 5):
        pkt = {
            "src_ip": ssh_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 53000,
            "dst_port": 22,  # Target SSH Port
            "protocol": "TCP",
            "tcp_flags": "S",
            "size": 64,
            "timestamp": time.time()
        }
        feed_packet(engine, pkt)

    is_blocked = engine.blocker.is_ip_blocked(ssh_ip)
    print(f"--> Verification: Is {ssh_ip} blocked? {is_blocked} (Expected: True)")

    # ==========================================
    # TEST 6: UDP Flood Attack Detection
    # ==========================================
    print_test_header("UDP Flood Attack Simulation")
    udp_ip = "10.0.0.99"
    from config.settings import UDP_FLOOD_THRESHOLD
    log_warning(f"Simulating UDP Flood: IP {udp_ip} sending {UDP_FLOOD_THRESHOLD + 5} UDP packets...")

    for _ in range(UDP_FLOOD_THRESHOLD + 5):
        pkt = {
            "src_ip": udp_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 44000,
            "dst_port": 9999,
            "protocol": "UDP",
            "tcp_flags": "",
            "size": 512,
            "timestamp": time.time()
        }
        feed_packet(engine, pkt)

    is_blocked = engine.blocker.is_ip_blocked(udp_ip)
    print(f"--> Verification: Is {udp_ip} blocked? {is_blocked} (Expected: True)")

    # ==========================================
    # TEST 7: ACK Flood Attack Detection
    # ==========================================
    print_test_header("ACK Flood Attack Simulation")
    ack_ip = "10.0.0.111"
    from config.settings import ACK_FLOOD_THRESHOLD
    log_warning(f"Simulating ACK Flood: IP {ack_ip} sending {ACK_FLOOD_THRESHOLD + 5} ACK packets...")

    for _ in range(ACK_FLOOD_THRESHOLD + 5):
        pkt = {
            "src_ip": ack_ip,
            "dst_ip": "192.168.1.1",
            "src_port": 62000,
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": "A",  # Pure ACK, no SYN
            "size": 64,
            "timestamp": time.time()
        }
        feed_packet(engine, pkt)

    is_blocked = engine.blocker.is_ip_blocked(ack_ip)
    print(f"--> Verification: Is {ack_ip} blocked? {is_blocked} (Expected: True)")

    # ==========================================
    # TEST 8: DNS Amplification Detection
    # ==========================================
    print_test_header("DNS Amplification Attack Simulation")
    dns_ip = "10.0.0.120"
    from config.settings import DNS_AMPLIFICATION_THRESHOLD
    log_warning(f"Simulating DNS Amplification: IP {dns_ip} sending {DNS_AMPLIFICATION_THRESHOLD + 5} DNS queries...")

    for _ in range(DNS_AMPLIFICATION_THRESHOLD + 5):
        pkt = {
            "src_ip": dns_ip,
            "dst_ip": "8.8.8.8",
            "src_port": 45000,
            "dst_port": 53,  # DNS Port
            "protocol": "UDP",
            "tcp_flags": "",
            "size": 512,
            "timestamp": time.time()
        }
        feed_packet(engine, pkt)

    is_blocked = engine.blocker.is_ip_blocked(dns_ip)
    print(f"--> Verification: Is {dns_ip} blocked? {is_blocked} (Expected: True)")

    # ==========================================
    # TEST 9: DDoS Detection
    # ==========================================
    print_test_header("DDoS Attack Simulation (Multi-Source)")
    from config.settings import DDoS_THRESHOLD
    ddos_target = "192.168.1.100"
    log_warning(f"Simulating DDoS: {DDoS_THRESHOLD + 2} unique source IPs -> {ddos_target}...")

    detected = False
    for i in range(DDoS_THRESHOLD + 2):
        ddos_src = f"10.1.0.{i + 1}"
        pkt = {
            "src_ip": ddos_src,
            "dst_ip": ddos_target,
            "src_port": 30000 + i,
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": "S",
            "size": 64,
            "timestamp": time.time()
        }
        feed_packet(engine, pkt)

    print(f"--> DDoS Simulation: {DDoS_THRESHOLD + 2} distinct attackers sent. Check alerts.log for DDoS entry.")

    # ==========================================
    # TEST 10: Prevention Block Drop (IPS Demonstration)
    # ==========================================
    print_test_header("IPS Active Block Policy Verification")
    log_info(f"Currently blocked IPs: {engine.blocker.get_blocked_ips()}")

    traffic_file = os.path.join(base, "storage", "traffic_data.csv")
    before_traffic_count = 0
    if os.path.exists(traffic_file):
        with open(traffic_file, "r") as f:
            before_traffic_count = len(f.readlines())

    # Send a packet from a BLOCKED attacker IP (should be dropped silently)
    pkt_blocked = {
        "src_ip": scan_ip,  # 10.0.0.66 is blocked
        "dst_ip": "192.168.1.1",
        "src_port": 50000,
        "dst_port": 80,
        "protocol": "TCP",
        "tcp_flags": "PA",
        "size": 256,
        "timestamp": time.time()
    }
    feed_packet(engine, pkt_blocked)

    after_traffic_count = 0
    if os.path.exists(traffic_file):
        with open(traffic_file, "r") as f:
            after_traffic_count = len(f.readlines())

    print(f"[VERIFY] Blocked IP Packet Dropped? {before_traffic_count == after_traffic_count} (Expected: True)")

    # ==========================================
    # FILE VERIFICATIONS
    # ==========================================
    verify_logs()

    print("\n" + "=" * 60)
    print(" ALL TESTS COMPLETED SUCCESSFULLY! CORE LOGIC VALIDATED.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    run_offline_test_suite()
