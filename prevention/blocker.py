import os
import time
import subprocess
import threading
import sys
from typing import Set, Dict
from config.settings import BLOCKED_IPS_FILE, BLOCK_TIME
try:
    from config.settings import EXECUTE_SYSTEM_BLOCK
except ImportError:
    EXECUTE_SYSTEM_BLOCK = False
from utils.helpers import log_info, log_warning, log_alert
from utils.time_utils import get_current_timestamp, get_epoch_time

class IPSBlocker:
    """
    IPSBlocker provides the Intrusion Prevention (IPS) capabilities.
    """
    def __init__(self, blocked_list_file: str = BLOCKED_IPS_FILE):
        # Maps blocked IP to unblock epoch timestamp
        self.blocked_file = blocked_list_file
        self.blocked_ips: Dict[str, float] = {}
        self.lock = threading.Lock()
        self.is_running = False
        self.unblock_thread = None
        
        # Load existing blocks from file
        self._load_blocked_ips()
        
    def start(self):
        """Starts the unblocking reaper background thread."""
        if self.is_running:
            return
        self.is_running = True
        self.unblock_thread = threading.Thread(target=self._unblock_reaper, name="IPSUnblockReaper", daemon=True)
        self.unblock_thread.start()
        log_info("IPS Prevention Engine active.")

    def stop(self):
        """Stops the engine reaper."""
        self.is_running = False

    def is_ip_blocked(self, ip: str) -> bool:
        """
        Check if an IP is currently in the active blocklist.
        """
        should_unblock = False
        with self.lock:
            if ip in self.blocked_ips:
                unblock_time = self.blocked_ips[ip]
                if unblock_time == 0 or get_epoch_time() < unblock_time:
                    return True
                else:
                    should_unblock = True
        
        if should_unblock:
            self.unblock_ip(ip)
            
        return False

    def is_blocked(self, ip: str) -> bool:
        """
        Backward compatibility wrapper mapping to is_ip_blocked().
        """
        return self.is_ip_blocked(ip)

    def block_ip(self, ip: str, duration: int = BLOCK_TIME, reason: str = ""):
        """
        Bans an IP address internally and executes OS firewall rules if configured.
        
        :param ip: Target malicious IP address.
        :param duration: Time in seconds to hold the ban. 0 for permanent.
        :param reason: String for logging context.
        """
        if ip in ("127.0.0.1", "::1"):
            # Refuse blocking localhost to prevent self-lockouts during simulations
            return
            
        now = get_epoch_time()
        unblock_time = 0.0 if duration == 0 else now + duration
        
        with self.lock:
            self.blocked_ips[ip] = unblock_time
            self._save_blocked_ips()
            
        log_alert(f"IPS banned IP: {ip} for {duration if duration > 0 else 'infinite'} seconds. Reason: {reason}")
        
        # Execute OS Firewall rules if enabled
        if EXECUTE_SYSTEM_BLOCK:
            self._apply_firewall_rule(ip)

    def unblock_ip(self, ip: str):
        """
        Removes an IP address ban.
        """
        with self.lock:
            if ip in self.blocked_ips:
                del self.blocked_ips[ip]
                self._save_blocked_ips()
                
        log_info(f"IPS unblocked IP: {ip}.")
        
        if EXECUTE_SYSTEM_BLOCK:
            self._remove_firewall_rule(ip)

    def get_blocked_ips(self) -> Set[str]:
        """Returns a snapshot copy of currently blocked IPs."""
        with self.lock:
            return set(self.blocked_ips.keys())

    def get_blocked_list(self) -> Set[str]:
        """Backward compatibility wrapper mapping to get_blocked_ips()."""
        return self.get_blocked_ips()

    def _unblock_reaper(self):
        """
        Thread loop running periodically to prune expired IP blocks from the tracking table.
        """
        while self.is_running:
            time.sleep(5)  # Run checks every 5 seconds
            now = get_epoch_time()
            expired_ips = []
            
            with self.lock:
                for ip, unblock_time in list(self.blocked_ips.items()):
                    if unblock_time > 0 and now >= unblock_time:
                        expired_ips.append(ip)
                        
            for ip in expired_ips:
                self.unblock_ip(ip)

    def _load_blocked_ips(self):
        """Loads IPs from storage/blocked_ips.txt on startup."""
        os.makedirs(os.path.dirname(self.blocked_file), exist_ok=True)
        if not os.path.exists(self.blocked_file):
            return
            
        try:
            with open(self.blocked_file, "r", encoding="utf-8") as f:
                for line in f:
                    ip = line.strip()
                    if ip:
                        self.blocked_ips[ip] = get_epoch_time() + BLOCK_TIME
        except Exception as e:
            log_warning(f"Could not load blocked IPs from file: {str(e)}")

    def _save_blocked_ips(self):
        """Saves current active blocked IPs to storage/blocked_ips.txt."""
        try:
            with open(self.blocked_file, "w", encoding="utf-8") as f:
                for ip in self.blocked_ips.keys():
                    f.write(f"{ip}\n")
        except Exception as e:
            log_warning(f"Could not save blocked IPs to file: {str(e)}")

    def _apply_firewall_rule(self, ip: str):
        """Hooks into OS command shells to drop traffic at the routing layer."""
        try:
            if sys.platform.startswith("linux"):
                cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
                subprocess.run(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == "win32":
                cmd = f"netsh advfirewall firewall add rule name=\"IDS_IPS_BLOCK_{ip}\" dir=in action=block remoteip={ip}"
                subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            log_warning(f"Failed to execute firewall shell command block: {str(e)}")

    def _remove_firewall_rule(self, ip: str):
        """Reverts local OS firewalls when an IP ban expires."""
        try:
            if sys.platform.startswith("linux"):
                cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
                subprocess.run(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            elif sys.platform == "win32":
                cmd = f"netsh advfirewall firewall delete rule name=\"IDS_IPS_BLOCK_{ip}\""
                subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            log_warning(f"Failed to execute firewall rule deletion: {str(e)}")

# Class aliases for backward compatibility with stubs
Blocker = IPSBlocker