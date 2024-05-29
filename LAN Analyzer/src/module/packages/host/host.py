"""
Author: Ofir Brovin.
This file contains the Host representation class of the LAN Analyzer application.
"""
from __future__ import annotations

import threading

from typing import Tuple

from PyQt5.QtCore import QTimer

from dataclasses import dataclass, field


@dataclass
class Host:
    """
    Host representation class
    required: Hostname, IP address, MAC address, mac vendor, response time
    """
    # Basic information:
    hostname: str
    ip_address: str
    mac_address: str
    mac_vendor: str
    response_time: int
    # Fingerprinting information:
    type: str = "computer"  # this can be changed after fingerprinting - computer / router / printer
    # PORTS
    scanned_ports: range | None = None
    open_ports: Tuple[list, list] | None = None  # [Open TCP ports, open UDP ports]
    closed_ports: Tuple[list, list] | None = None  # [Closed TCP ports, closed UDP ports]
    filtered_ports: Tuple[list, list] | None = None  # [Filtered TCP ports, filtered UDP ports]
    # OS
    operating_sys: str = ""
    # FLAG
    flagged: bool = False  # Flagged by the user in the topology / hosts connector
    # CONNECTED WITH CONNECTOR SCRIPT
    script_connected: bool = False
    # FINGERPRINTING SCANS VARS
    fp_scan_in_progress: bool = False
    current_fp_scan: str = ""  # The network fp scan CONST str (WELL_KNOWN_PORT_SCAN = "well-known-ps" ...)
    current_fp_scan_str: str = ""  # The "pretty" fp scan str to show in the GUI
    fp_scans_queue: list = field(default_factory=list)  # Default empty list for the fp scans queue
    # Fp scan progress vars
    fp_scan_progress_value: int | None = None
    max_fp_scan_prog_value: int | None = None
    fp_scan_progress_timer: QTimer | None = None
    fp_scan_progress_lock: threading.Lock | None = None
    # Stop fp scan vars
    stop_fp_scan_flag: threading.Event | None = None
    stop_fp_scan_flag_lock: threading.Lock | None = None
    # (View) Windows:
    information_window = None  # HostInformationWindow
    advanced_ports_window = None  # AdvancedPortsInfoWindow
    warning_window = None  # SendWarningWindow
    
    def clear_fp_scans_queue(self) -> None:
        """
        Clears the host's fingerprinting scans queue.
        Updates the host's info and management window fp scans section.
        Called when the bin button pressed within the host's info and management window.
        :return: None
        """
        self.fp_scans_queue.clear()
        if self.information_window is not None:
            self.information_window.update_fp_scans_section()
    
    def stop_running_fp_scan(self) -> None:
        """
        Stops the host's in-progress fingerprinting scan (sets its stop flag).
        Called when cancel (X) button pressed within the host's info and management window.
        :return: None
        """
        with self.stop_fp_scan_flag_lock:
            if not self.stop_fp_scan_flag.is_set():
                self.stop_fp_scan_flag.set()
