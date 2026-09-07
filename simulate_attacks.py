import sys
import os
import time
import socket
import json
from scapy.all import IP, TCP, UDP, ICMP, send

# Adjust path to find config/utils
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from utils.helpers import log_info, log_warning, log_alert
from config.settings import PORT_SCAN_THRESHOLD, SYN_FLOOD_THRESHOLD, ICMP_FLOOD_THRESHOLD, BRUTE_FORCE_THRESHOLD

UDP_SIM_PORT = 55555

def transmit_packet(pkt_dict: dict, raw_scapy_pkt):
    """
    Attempts to transmit packet via raw Scapy socket injection.
    If it fails due to driver/permission issues, transmits via UDP loopback to the sniffer socket!
    """
    try:
        # Try raw Scapy send
        send(raw_scapy_pkt, verbose=0)
    except Exception:
        # Fallback to local UDP socket simulation
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            payload = json.dumps(pkt_dict).encode("utf-8")
            sock.sendto(payload, ("127.0.0.1", UDP_SIM_PORT))
            sock.close()
        except Exception as e:
            log_warning(f"Fallback simulation transmission failed: {str(e)}")

def simulate_port_scan(target_ip: str, attacker_ip: str):
    """
    Simulates a Port Scan attack targeting a range of unique ports.
    """
    log_info(f"Simulating Port Scan from Attacker: {attacker_ip} -> Target: {target_ip}...")
    log_warning(f"Generating {PORT_SCAN_THRESHOLD + 5} unique port hits. Threshold is {PORT_SCAN_THRESHOLD}.")
    
    for port in range(1, PORT_SCAN_THRESHOLD + 5):
        pkt_dict = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": 50000,
            "dst_port": port,
            "protocol": "UDP",
            "tcp_flags": "",
            "size": 42,
            "timestamp": time.time()
        }
        raw_pkt = IP(src=attacker_ip, dst=target_ip) / UDP(sport=50000, dport=port)
        transmit_packet(pkt_dict, raw_pkt)
        time.sleep(0.05)
        
    log_info("Port Scan Simulation packet injection complete.")

def simulate_syn_flood(target_ip: str, attacker_ip: str):
    """
    Simulates a SYN Flood DDoS attack.
    """
    log_info(f"Simulating SYN Flood from Attacker: {attacker_ip} -> Target: {target_ip}...")
    log_warning(f"Generating {SYN_FLOOD_THRESHOLD + 10} SYN packets. Threshold is {SYN_FLOOD_THRESHOLD}.")
    
    for _ in range(SYN_FLOOD_THRESHOLD + 10):
        pkt_dict = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": 61000,
            "dst_port": 80,
            "protocol": "TCP",
            "tcp_flags": "S",
            "size": 64,
            "timestamp": time.time()
        }
        raw_pkt = IP(src=attacker_ip, dst=target_ip) / TCP(sport=61000, dport=80, flags="S")
        transmit_packet(pkt_dict, raw_pkt)
        time.sleep(0.01)
        
    log_info("SYN Flood Simulation packet injection complete.")

def simulate_icmp_flood(target_ip: str, attacker_ip: str):
    """
    Simulates an ICMP Ping flood.
    """
    log_info(f"Simulating ICMP Flood from Attacker: {attacker_ip} -> Target: {target_ip}...")
    log_warning(f"Generating {ICMP_FLOOD_THRESHOLD + 10} ICMP packets. Threshold is {ICMP_FLOOD_THRESHOLD}.")
    
    for _ in range(ICMP_FLOOD_THRESHOLD + 10):
        pkt_dict = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": 8, # Echo Request type
            "dst_port": 0,
            "protocol": "ICMP",
            "tcp_flags": "",
            "size": 32,
            "timestamp": time.time()
        }
        raw_pkt = IP(src=attacker_ip, dst=target_ip) / ICMP(type=8, code=0)
        transmit_packet(pkt_dict, raw_pkt)
        time.sleep(0.01)
        
    log_info("ICMP Flood Simulation packet injection complete.")

def simulate_brute_force(target_ip: str, attacker_ip: str):
    """
    Simulates an SSH Authentication Brute-Force attack targeting port 22.
    """
    log_info(f"Simulating SSH Brute-Force from Attacker: {attacker_ip} -> Target: {target_ip}...")
    log_warning(f"Generating {BRUTE_FORCE_THRESHOLD + 5} login attempts. Threshold is {BRUTE_FORCE_THRESHOLD}.")
    
    for _ in range(BRUTE_FORCE_THRESHOLD + 5):
        pkt_dict = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": 55000,
            "dst_port": 22,
            "protocol": "TCP",
            "tcp_flags": "S",
            "size": 64,
            "timestamp": time.time()
        }
        raw_pkt = IP(src=attacker_ip, dst=target_ip) / TCP(sport=55000, dport=22, flags="S")
        transmit_packet(pkt_dict, raw_pkt)
        time.sleep(0.05)
        
    log_info("SSH Brute Force Simulation packet injection complete.")

if __name__ == "__main__":
    TARGET = "192.168.1.99"
    ATTACKER_IP = "10.0.0.66"
    
    banner = f"""
======================================================================
                    I D S  /  I P S   S I M U L A T O R
======================================================================
  [1] Simulate Port Scan (Targets multiple ports)
  [2] Simulate SYN Flood DDoS (Targets TCP Port 80)
  [3] Simulate ICMP Ping Flood
  [4] Simulate SSH Brute-Force (Targets TCP Port 22)
  [5] Simulate All Attacks Sequentially
======================================================================
"""
    print(banner)
    choice = input("Enter simulation option [1-5]: ").strip()
    
    print("\n[!] IDS/IPS simulation is running.")
    print("If raw packet driver is not present, it will automatically fall back")
    print("to loopback UDP socket simulation on port 55555.\n")
    
    try:
        if choice == "1":
            simulate_port_scan(TARGET, ATTACKER_IP)
        elif choice == "2":
            simulate_syn_flood(TARGET, "10.0.0.77")
        elif choice == "3":
            simulate_icmp_flood(TARGET, "10.0.0.88")
        elif choice == "4":
            simulate_brute_force(TARGET, "10.0.0.55")
        elif choice == "5":
            simulate_port_scan(TARGET, "10.0.0.66")
            time.sleep(2)
            simulate_syn_flood(TARGET, "10.0.0.77")
            time.sleep(2)
            simulate_icmp_flood(TARGET, "10.0.0.88")
            time.sleep(2)
            simulate_brute_force(TARGET, "10.0.0.55")
        else:
            log_alert("Invalid option. Exiting simulation.")
    except Exception as e:
        log_alert(f"Simulation interrupted: {str(e)}")
