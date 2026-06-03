#!/usr/bin/env python3
"""
PacketShield IDS/IPS – Numeric Menu Interface (Clear fixed, no duplicate menu)
"""

import sys
import os
import time
import signal
import platform
import termios
import tty
from typing import Dict, Any

# ========== Global raw mode for clean input ==========
fd = sys.stdin.fileno()
old_settings = termios.tcgetattr(fd)

def enable_raw_mode():
    new = termios.tcgetattr(fd)
    new[3] = new[3] & ~(termios.ECHO | termios.ICANON)
    termios.tcsetattr(fd, termios.TCSADRAIN, new)
    sys.stdout.write('\033[?1000l\033[?1002l\033[?1003l')
    sys.stdout.flush()

def restore_terminal():
    termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    sys.stdout.write('\033[?1000h\033[?1002h\033[?1003h')
    sys.stdout.flush()

def getch():
    return sys.stdin.read(1)

def raw_input(prompt=""):
    sys.stdout.write(prompt)
    sys.stdout.flush()
    buffer = ""
    while True:
        c = getch()
        if c == '\r' or c == '\n':
            sys.stdout.write('\n')
            sys.stdout.flush()
            return buffer
        elif c == '\x7f' or c == '\b':
            if buffer:
                buffer = buffer[:-1]
                sys.stdout.write('\b \b')
                sys.stdout.flush()
        elif c == '\033':
            getch()
            getch()
        elif c.isprintable() or c == ' ':
            buffer += c
            sys.stdout.write(c)
            sys.stdout.flush()

# ========== Persistent banner and screen ==========
def clear_screen():
    os.system('clear' if platform.system() != 'Windows' else 'cls')

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.banner import print_banner

def init_screen():
    clear_screen()
    print_banner()
    print("\n" + "=" * 60)
    print("          PacketShield IDS/IPS - Main Menu")
    print("=" * 60)

def clear_dynamic_area():
    sys.stdout.write('\033[J')
    sys.stdout.flush()

def show_menu():
    """Display the numeric menu in the dynamic area."""
    clear_dynamic_area()
    print("\n" + "-" * 50)
    print("  MAIN MENU")
    print("-" * 50)
    print("  1. Start Monitoring (IDS/IPS Engine)")
    print("  2. Show Help")
    print("  3. Show Blocked IPs")
    print("  4. Show Alert Logs")
    print("  5. Clear Screen (Full Reset)")
    print("  6. Exit")
    print("-" * 50)
    print()

# ========== Menu actions ==========
def show_help():
    """Display the detailed help text."""
    help_text = """
================================================================================
                            PACKETSHIELD HELP MENU
================================================================================

PacketShield is a lightweight Integrated Network IDS & IPS framework designed
to monitor live network traffic, detect suspicious activities, and prevent
basic network attacks in real-time.

------------------------------------------------------------------------------
WHAT IS PACKETSHIELD?
------------------------------------------------------------------------------

PacketShield works as both:

1. IDS (Intrusion Detection System)   -> Detects suspicious or malicious traffic.
2. IPS (Intrusion Prevention System)  -> Automatically blocks attacker IP addresses.

The framework continuously monitors packets flowing through the network and
analyzes them using detection engines.

------------------------------------------------------------------------------
HOW PACKETSHIELD WORKS
------------------------------------------------------------------------------

Network Traffic -> Packet Sniffer -> Packet Analyzer -> Threat Detection Engines
-> Alert Generation -> IPS Prevention & Blocking

------------------------------------------------------------------------------
SUPPORTED ATTACK DETECTION (including DoS attacks)
------------------------------------------------------------------------------

- Port Scan (SYN, FIN, NULL, Xmas)   | - SYN Flood (DoS)
- ICMP Flood (Ping) (DoS)            | - UDP Flood (DoS)
- ACK Flood (DoS)                    | - DNS Amplification (DoS)
- Brute Force (SSH, FTP, Telnet)     | - ARP Spoofing (MITM)

All flood attacks are Denial‑of‑Service (DoS) attacks.

------------------------------------------------------------------------------
AVAILABLE MENU OPTIONS
------------------------------------------------------------------------------

1. Start Monitoring     – Begins real‑time capture and detection. Press Ctrl+C to stop.
2. Show Help            – Displays this detailed information.
3. Show Blocked IPs     – Lists currently blocked IP addresses.
4. Show Alert Logs      – Displays the last 15 alerts from storage/alerts.log.
5. Clear Screen         – Clears the entire terminal and redraws the banner & menu.
6. Exit                 – Terminates PacketShield safely.

------------------------------------------------------------------------------
HOW IPS BLOCKING WORKS
------------------------------------------------------------------------------

When an attack is detected:
1. Threat engine validates the behavior.
2. An alert is generated and logged.
3. The attacker IP is added to the blocked list.
4. All future packets from that IP are ignored.

------------------------------------------------------------------------------
CONFIGURATION & LOGS
------------------------------------------------------------------------------

- Configuration: config/settings.py (thresholds, interface, block time)
- Alert logs:    storage/alerts.log
- Blocked IPs:   storage/blocked_ips.txt
- Traffic stats: storage/traffic_data.csv

------------------------------------------------------------------------------
IMPORTANT NOTES
------------------------------------------------------------------------------

[!] Run with root/sudo on Linux, or as Administrator on Windows (with Npcap).
[!] Linux is recommended for stable packet capture.
[!] This tool is for educational and defensive security purposes.

------------------------------------------------------------------------------
EXAMPLE USAGE
------------------------------------------------------------------------------

$ sudo python3 main.py
(menu appears)
Enter choice: 1   # starts monitoring
(Press Ctrl+C to stop)
Enter choice: 3   # shows blocked IPs
Enter choice: 5   # clears screen and resets menu
Enter choice: 6   # exits

================================================================================
                            PacketShield v1.0
================================================================================
"""
    clear_dynamic_area()
    print(help_text)
    input("\nPress Enter to return to menu...")

def show_blocks():
    """Display currently blocked IPs."""
    clear_dynamic_area()
    print("\n" + "-" * 50)
    print("CURRENTLY BLOCKED IP ADDRESSES")
    print("-" * 50)
    blocked_file = "storage/blocked_ips.txt"
    if os.path.exists(blocked_file):
        with open(blocked_file, 'r') as f:
            blocked = [line.strip() for line in f if line.strip()]
        if blocked:
            for ip in blocked:
                print(f"  {ip}")
        else:
            print("  No IPs are currently blocked.")
    else:
        print("  No blocked IPs file found yet.")
    print("-" * 50)
    input("\nPress Enter to return to menu...")

def show_logs():
    """Display recent alerts."""
    clear_dynamic_area()
    print("\n" + "-" * 50)
    print("RECENT ALERT LOGS (last 15 lines)")
    print("-" * 50)
    alerts_file = "storage/alerts.log"
    if os.path.exists(alerts_file):
        with open(alerts_file, 'r') as f:
            lines = f.readlines()
        if lines:
            for line in lines[-15:]:
                print(f"  {line.strip()}")
        else:
            print("  No alerts recorded yet.")
    else:
        print("  No alerts log file found yet.")
    print("-" * 50)
    input("\nPress Enter to return to menu...")

def full_reset():
    """Clear entire screen and redraw banner + menu from scratch."""
    init_screen()
    show_menu()

def start_monitoring():
    """Launch the IDS/IPS engine."""
    clear_dynamic_area()
    print("\n" + "-" * 50)
    print("STARTING MONITORING MODE (Press Ctrl+C to stop)")
    print("-" * 50 + "\n")

    engine = NetworkIDSIPS()
    try:
        engine.start()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"\n[ERROR] Engine crashed: {e}")
    finally:
        print("\n" + "-" * 50)
        print("Monitoring stopped. Returning to menu.")
        print("-" * 50)
        input("Press Enter to continue...")

# ========== IDS/IPS Engine (unchanged) ==========
from config.settings import INTERFACE
from utils.helpers import log_info, log_warning, log_alert
from sniffer.packet_sniffer import PacketSniffer
from analyzer.packet_analyzer import PacketAnalyzer
from detection.port_scan_detector import PortScanDetector
from detection.syn_flood_detector import SynFloodDetector
from detection.icmp_flood_detector import ICMPFloodDetector
from detection.brute_force_detector import BruteForceDetector
from detection.ack_flood_detector import ACKFloodDetector
from detection.udp_flood_detector import UDPFloodDetector
from detection.dns_amplification_detector import DNSAmplificationDetector
from detection.arp_spoof_detector import ARPSpoofDetector
from prevention.blocker import Blocker
from logger.logger import IDSLogger

class NetworkIDSIPS:
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
            DNSAmplificationDetector()
        ]
        self.arp_detector = ARPSpoofDetector()
        self.sniffer = PacketSniffer(interface=INTERFACE, packet_callback=self._handle_packet)
        self.is_running = False

    def start(self):
        self.is_running = True
        self.blocker.start()
        self.sniffer.start()
        log_info("IDS/IPS Engine is fully armed. Press Ctrl+C to stop.")
        def sigint_handler(sig, frame):
            self.stop()
        signal.signal(signal.SIGINT, sigint_handler)
        try:
            while self.is_running:
                time.sleep(2)
                blocked = self.blocker.get_blocked_ips()
                captured = self.sniffer.get_stats()
                sys.stdout.write(f"\r[STATUS] Sniffed: {captured} packets | Active Blocks: {len(blocked)} IPs")
                sys.stdout.flush()
        except Exception as e:
            if self.is_running:
                log_alert(f"Engine error: {str(e)}")
        finally:
            self.stop()

    def stop(self):
        if not self.is_running:
            return
        print()
        log_warning("Shutting down IDS/IPS Engine...")
        self.is_running = False
        self.sniffer.stop()
        self.blocker.stop()
        log_info("IDS/IPS Engine terminated.")

    def _handle_packet(self, raw_packet):
        try:
            is_spoof, spoof_ip, new_mac = self.arp_detector.process_arp_packet(raw_packet)
            if is_spoof:
                self._trigger_prevention("ARP Spoofing", spoof_ip, f"MAC changed to {new_mac}")
            packet_info = PacketAnalyzer.analyze(raw_packet)
            if not packet_info:
                return
            src_ip = packet_info["src_ip"]
            if self.blocker.is_ip_blocked(src_ip):
                return
            self.logger.log_traffic(packet_info)
            self._evaluate_threats(packet_info)
        except Exception as e:
            log_warning(f"Packet handling error: {str(e)}")

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

# ========== Main loop with numeric menu (fixed duplicate on clear) ==========
def main():
    enable_raw_mode()
    init_screen()
    show_menu()
    while True:
        choice = raw_input("Enter your choice (1-6): ").strip()
        if choice == '1':
            start_monitoring()
            show_menu()
        elif choice == '2':
            show_help()
            show_menu()
        elif choice == '3':
            show_blocks()
            show_menu()
        elif choice == '4':
            show_logs()
            show_menu()
        elif choice == '5':
            full_reset()
            # Do NOT call show_menu() again – full_reset already printed it
        elif choice == '6':
            restore_terminal()
            clear_screen()
            print("Thank you for using PacketShield. Goodbye!")
            sys.exit(0)
        else:
            clear_dynamic_area()
            print(f"\nInvalid choice: '{choice}'. Please enter a number 1-6.\n")
            input("Press Enter to continue...")
            show_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        restore_terminal()
        clear_screen()
        print("\nExited by user.")
        sys.exit(0)
    except Exception as e:
        restore_terminal()
        print(f"\nFATAL ERROR: {e}")
        sys.exit(1)