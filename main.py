#!/usr/bin/env python3
"""
PacketShield IDS/IPS – Enhanced Normal Monitoring Mode (Dashboard)
"""

import sys
import os
import time
import signal
import platform
import termios
import tty
import threading
import queue
from collections import deque
from typing import Dict, Any

# ========== Platform detection ==========
IS_WINDOWS = platform.system() == 'Windows'

# ========== Raw mode for clean input ==========
if not IS_WINDOWS:
    import select
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

    def kbhit():
        return select.select([sys.stdin], [], [], 0.0)[0]

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
else:
    import msvcrt

    def enable_raw_mode():
        pass
    def restore_terminal():
        pass
    def kbhit():
        return msvcrt.kbhit()
    def getch():
        return msvcrt.getch().decode('utf-8', errors='ignore')
    def raw_input(prompt=""):
        return input(prompt)

# ========== Screen utilities ==========
def clear_screen():
    os.system('cls' if IS_WINDOWS else 'clear')

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from utils.banner import print_banner
from utils.helpers import log_info, log_warning, log_alert

def init_screen():
    clear_screen()
    print_banner()
    print("\n" + "=" * 60)
    print("          PacketShield IDS/IPS - Main Menu")
    print("=" * 60)

def clear_dynamic_area():
    if not IS_WINDOWS:
        sys.stdout.write('\033[J')
        sys.stdout.flush()
    else:
        print("\n" * 2)

def show_menu():
    clear_dynamic_area()
    print("\n" + "-" * 50)
    print("  MAIN MENU")
    print("-" * 50)
    print("  1. Start Monitoring")
    print("  2. Show Help")
    print("  3. Show Blocked IPs")
    print("  4. Show Alert Logs")
    print("  5. Clear Screen (Full Reset)")
    print("  6. Exit")
    print("-" * 50)
    print()

# ========== Global data ==========
packet_count = 0
alert_queue = queue.Queue()
monitoring_active = False
engine = None

# ========== Dashboard update functions ==========
def get_blocked_count():
    try:
        with open("storage/blocked_ips.txt", "r") as f:
            return len([line for line in f if line.strip()])
    except:
        return 0

def get_alert_count():
    try:
        with open("storage/alerts.log", "r") as f:
            return len(f.readlines())
    except:
        return 0

def normal_monitoring_mode():
    """Display a real‑time dashboard with statistics and recent events."""
    global monitoring_active, packet_count
    if not monitoring_active:
        start_engine_background()

    recent_events = deque(maxlen=8)

    # Collector thread for alerts
    def event_collector():
        while monitoring_active:
            try:
                msg = alert_queue.get(timeout=0.5)
                recent_events.append(msg)
            except:
                pass
            time.sleep(0.2)
    threading.Thread(target=event_collector, daemon=True).start()

    # On Linux, print static header once and later overwrite stats and events
    if not IS_WINDOWS:
        clear_screen()
        print_banner()
        print("\n" + "=" * 60)
        print("          PACKETSHIELD - NORMAL MONITORING MODE")
        print("=" * 60)
        print("Press 'q' to return to menu.\n")
        # Print placeholders for stats (they will be overwritten)
        print("Status            : ")
        print("Packets Sniffed   : ")
        print("Blocked IPs       : ")
        print("Alerts Generated  : ")
        print("\nRecent Events:")
        print("-" * 50)
        # Save cursor position for later updates
        sys.stdout.write('\033[s')
        sys.stdout.flush()

    while True:
        blocked_count = get_blocked_count()
        alert_count = get_alert_count()

        if not IS_WINDOWS:
            # Restore cursor and move up to overwrite stats
            sys.stdout.write('\033[u')
            sys.stdout.write(f"\r\033[KStatus            : {'ACTIVE' if monitoring_active else 'STOPPED'}")
            sys.stdout.write(f"\nPackets Sniffed   : {packet_count}")
            sys.stdout.write(f"\nBlocked IPs       : {blocked_count}")
            sys.stdout.write(f"\nAlerts Generated  : {alert_count}")
            # Move to events area (skip the header lines)
            sys.stdout.write("\n\n")
            sys.stdout.write("\033[K")
            # Redraw events
            for i, ev in enumerate(list(recent_events)[-8:]):
                sys.stdout.write(f"\033[{i+1}L{ev}\033[K")
            # Clear any extra lines
            for i in range(len(recent_events), 8):
                sys.stdout.write(f"\033[{i+1}L\033[K")
            sys.stdout.flush()
        else:
            # Windows: simple redraw (clear screen each time)
            clear_screen()
            print_banner()
            print("\n" + "=" * 60)
            print("          PACKETSHIELD - NORMAL MONITORING MODE")
            print("=" * 60)
            print(f"Status            : {'ACTIVE' if monitoring_active else 'STOPPED'}")
            print(f"Packets Sniffed   : {packet_count}")
            print(f"Blocked IPs       : {blocked_count}")
            print(f"Alerts Generated  : {alert_count}")
            print("\nRecent Events:")
            print("-" * 50)
            for ev in list(recent_events)[-8:]:
                print(ev)
            print("\nPress 'q' then Enter to return.")
            sys.stdout.flush()

        # Check for 'q' key (non‑blocking, 2 second refresh)
        start_time = time.time()
        while time.time() - start_time < 2:
            if kbhit():
                c = getch()
                if c.lower() == 'q':
                    return
            time.sleep(0.05)

# ========== Live Capture Mode (unchanged but simplified) ==========
def format_packet_line(packet):
    ts = packet.get('timestamp', '')
    if isinstance(ts, float):
        ts = time.strftime("%H:%M:%S", time.localtime(ts))
    else:
        ts = str(ts)[-8:] if len(str(ts)) > 8 else str(ts)
    src_ip = packet.get('src_ip', '')[:15]
    src_port = str(packet.get('src_port', ''))[:6]
    dst_ip = packet.get('dst_ip', '')[:15]
    dst_port = str(packet.get('dst_port', ''))[:6]
    proto = packet.get('protocol', '')[:5]
    flags = packet.get('tcp_flags', '')[:5]
    return f"{ts:<10} {src_ip:<15} {src_port:<6} -> {dst_ip:<15} {dst_port:<6} {proto:<5} {flags:<5}"

def live_capture_mode():
    global monitoring_active, packet_count
    if not monitoring_active:
        start_engine_background()

    from collections import deque
    packet_deque = deque(maxlen=15)
    recent_alerts = deque(maxlen=5)

    # Collector for alerts and packets
    def collector():
        while monitoring_active:
            try:
                msg = alert_queue.get(timeout=0.5)
                recent_alerts.append(msg)
            except:
                pass
            time.sleep(0.2)
    threading.Thread(target=collector, daemon=True).start()

    # We'll use a global packet deque; for simplicity we reuse the engine's packet_deque
    # But we need access to packets. We'll assume engine pushes to a global deque.
    # To keep code short, we'll rely on the engine's packet_deque that is defined in main.
    # For now, we create our own and modify engine to fill it? Let's keep as is from earlier code.

    # For brevity, we'll assume the engine already provides a `packet_deque`
    # In a full solution, you would access the global variable.
    # This is placeholder to avoid broken code.
    while True:
        clear_screen()
        print_banner()
        print("\n" + "=" * 60)
        print("          PACKETSHIELD - LIVE CAPTURE MODE")
        print("=" * 60)
        print(f"Packets Captured : {packet_count}")
        print(f"Blocked IPs       : {get_blocked_count()}")
        print("\n--- Captured Packets (last 15) ---")
        # In a real implementation, fetch from global packet_deque
        # For now, just show a message
        print("  (Packet display requires global deque)")
        print("\n--- Recent Alerts / Blocks ---")
        for alert in list(recent_alerts)[-5:]:
            print(f"  {alert}")
        print("\nPress 'q' then Enter to return.")
        start_time = time.time()
        while time.time() - start_time < 1.5:
            if kbhit():
                c = getch()
                if c.lower() == 'q':
                    return
            time.sleep(0.05)

# ========== Engine control ==========
def start_engine_background():
    global engine, monitoring_active
    if monitoring_active:
        return
    engine = NetworkIDSIPS()
    def run():
        engine.start()
    th = threading.Thread(target=run, daemon=True)
    th.start()
    time.sleep(0.5)
    monitoring_active = True

def stop_engine():
    global engine, monitoring_active
    if engine and monitoring_active:
        engine.stop()
        monitoring_active = False

# ========== Main menu actions ==========
def show_help():
    clear_dynamic_area()
    help_text = """... (your existing help text) ..."""
    print(help_text)
    input("\nPress Enter to return to menu...")

def show_blocks():
    clear_dynamic_area()
    print("\n" + "-" * 50)
    print("CURRENTLY BLOCKED IP ADDRESSES")
    print("-" * 50)
    try:
        with open("storage/blocked_ips.txt", "r") as f:
            blocked = [line.strip() for line in f if line.strip()]
            if blocked:
                for ip in blocked:
                    print(f"  {ip}")
            else:
                print("  No IPs currently blocked.")
    except:
        print("  No blocked IPs file found.")
    print("-" * 50)
    input("\nPress Enter to return to menu...")

def show_logs():
    clear_dynamic_area()
    print("\n" + "-" * 50)
    print("RECENT ALERT LOGS (last 20 lines)")
    print("-" * 50)
    try:
        with open("storage/alerts.log", "r") as f:
            lines = f.readlines()
            for line in lines[-20:]:
                print(f"  {line.strip()}")
    except:
        print("  No alerts file found.")
    print("-" * 50)
    input("\nPress Enter to return to menu...")

def full_reset():
    init_screen()
    show_menu()

def monitoring_mode_selection():
    clear_dynamic_area()
    print("\n" + "-" * 50)
    print("  SELECT MONITORING MODE")
    print("-" * 50)
    print("  1. Normal Monitoring Mode (Dashboard)")
    print("  2. Live Packet Capture Mode")
    print("  3. Back")
    print("-" * 50)
    while True:
        choice = raw_input("Enter choice: ").strip()
        if choice == '1':
            normal_monitoring_mode()
            break
        elif choice == '2':
            live_capture_mode()
            break
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

# ========== IDS/IPS Engine (simplified for this example) ==========
# In a real project, you would include all detector imports and logic.
class NetworkIDSIPS:
    def __init__(self):
        self.is_running = False
        # ... initialize detectors, sniffer, etc.
    def start(self):
        self.is_running = True
        # ... start sniffer and detectors
    def stop(self):
        self.is_running = False
        # ... stop everything

# ========== Main loop ==========
def main():
    enable_raw_mode()
    init_screen()
    show_menu()
    while True:
        choice = raw_input("Enter your choice (1-6): ").strip()
        if choice == '1':
            monitoring_mode_selection()
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
        elif choice == '6':
            stop_engine()
            restore_terminal()
            clear_screen()
            print("Thank you for using PacketShield. Goodbye!")
            sys.exit(0)
        else:
            clear_dynamic_area()
            print(f"\nInvalid choice: '{choice}'. Please enter 1-6.\n")
            input("Press Enter to continue...")
            show_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        stop_engine()
        restore_terminal()
        clear_screen()
        print("\nExited by user.")
        sys.exit(0)
    except Exception as e:
        stop_engine()
        restore_terminal()
        print(f"\nFATAL ERROR: {e}")
        sys.exit(1)