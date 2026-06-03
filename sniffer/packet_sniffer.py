import threading
import time
import socket
import json
from typing import Callable, Any
from scapy.all import sniff, IP, TCP, UDP, ICMP
from utils.helpers import log_info, log_warning, log_alert

class PacketSniffer:
    """
    PacketSniffer binds to a specified network interface and captures live packets.
    It passes every captured packet to a registered callback handler (normally the PacketAnalyzer).
    
    Resilience Upgrade:
    - If Npcap or WinPcap is not installed on Windows (or if permission is denied),
      the sniffer automatically falls back to an Offline/Simulation Socket Listener 
      bound to 127.0.0.1:55555. This allows cross-process testing without system errors!
    """
    def __init__(self, interface: str = None, packet_callback: Callable[[Any], None] = None, callback: Callable[[Any], None] = None):
        """
        :param interface: Name of the interface. If None, Scapy defaults.
        :param packet_callback: Primary callback function called when a packet is successfully sniffed.
        :param callback: Alternative callback for backward compatibility with stubs.
        """
        self.interface = interface
        self.packet_callback = packet_callback or callback
        self.is_running = False
        self.sniffer_thread = None
        self._captured_count = 0
        
        # Socket fallback details
        self.socket_thread = None
        self.udp_socket = None
        
    def start(self):
        """
        Starts the sniffing engine inside a background thread.
        """
        if self.is_running:
            log_warning("Packet sniffer is already running.")
            return

        self.is_running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_loop, name="SnifferThread", daemon=True)
        self.sniffer_thread.start()
        log_info(f"Packet sniffing engine started on interface: {self.interface or 'default/all'}")

    def stop(self):
        """
        Stops the sniffing engine.
        """
        self.is_running = False
        if self.udp_socket:
            try:
                self.udp_socket.close()
            except Exception:
                pass
        log_info("Stopping packet sniffing engine...")

    def _sniff_loop(self):
        """
        Internal loop calling Scapy's native sniff() function.
        If a permission error or driver exception occurs, it falls back to a local UDP loopback server.
        """
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                filter="ip",
                store=0,
                stop_filter=lambda x: not self.is_running
            )
        except (PermissionError, OSError, ValueError) as e:
            log_warning("Npcap/WinPcap capture driver not detected or insufficient permissions.")
            log_warning(f"Error details: {str(e)}")
            self._start_udp_simulation_fallback()
        except Exception as e:
            err_msg = str(e)
            if "winpcap" in err_msg.lower() or "pcap" in err_msg.lower() or "permission" in err_msg.lower():
                log_warning("Npcap/WinPcap capture driver not detected or insufficient privileges.")
                log_warning(f"Error details: {err_msg}")
            else:
                log_alert(f"Sniffer encountered an unexpected runtime exception: {err_msg}")
            self._start_udp_simulation_fallback()

    def _start_udp_simulation_fallback(self):
        """
        Spawns a local loopback UDP socket listener on port 55555.
        This provides a secure mock packet feed mechanism across different processes!
        """
        log_info("Falling back to local UDP Socket Simulation Listener on 127.0.0.1:55555...")
        
        self.socket_thread = threading.Thread(target=self._udp_socket_loop, name="UDPSimulationThread", daemon=True)
        self.socket_thread.start()

    def _udp_socket_loop(self):
        """
        Reads stringified/JSON packet metadata from UDP socket port 55555.
        """
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.udp_socket.bind(("127.0.0.1", 55555))
        except Exception as e:
            log_alert(f"Failed to bind simulation socket to port 55555: {str(e)}")
            return
            
        while self.is_running:
            try:
                data, addr = self.udp_socket.recvfrom(65535)
                if not data:
                    continue
                    
                # Decode JSON representation of packet
                payload = json.loads(data.decode("utf-8"))
                
                # Increment statistics
                self._captured_count += 1
                
                # Forward to handler callback
                if self.packet_callback:
                    self.packet_callback(payload)
                    
            except socket.error:
                # Socket was likely closed on stop()
                break
            except Exception as e:
                log_warning(f"Error handling simulated UDP packet payload: {str(e)}")

    def _process_packet(self, packet):
        """
        Processes captured live packets and hands them off to the analyzer callback.
        """
        if not self.is_running:
            return
            
        self._captured_count += 1
        
        if self.packet_callback:
            try:
                self.packet_callback(packet)
            except Exception as e:
                log_warning(f"Error executing packet callback handler: {str(e)}")

    def get_stats(self) -> int:
        """Returns the total number of packets captured since startup."""
        return self._captured_count