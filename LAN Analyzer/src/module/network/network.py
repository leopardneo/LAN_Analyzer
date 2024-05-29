"""
Author: Ofir Brovin.
This file contains the network module of the LAN Analyzer application.
"""
from __future__ import annotations

import sys
if __name__ == '__main__':
    sys.exit("This file is part of the LAN Analyzer application and cannot be run independently")

import os
import time
import logging
import threading

from typing import Dict

from PyQt5.QtCore import pyqtSignal, QObject, QTimer, QCoreApplication, QEvent

from scapy.all import conf
from scapy.sendrecv import sr1
from scapy.layers.inet import IP, ICMP

from ..packages.util.interfaces_discovery import discover_network_interfaces
from ..packages.util.ip_address_functions import get_subnet_addresses_from_cidr, get_addresses_between, ip_to_int

from ..packages.host import Host
from ..packages.scanner import NetworkScanner
from ..packages.os_fp import OsDetector
from ..packages.port_scanner import PortScanner
from ..packages.mac_vendor_lookup import MacVendorLookup
from ..packages.ports_services_lookup import PortServiceLookup
from ..packages.hosts_connector import AnalyzerHostsConnector
from ..packages.sniffer import AnalyzerTrafficSniffer


class AnalyzerNetwork(QObject):
    """
    The LAN Analyzer network module class.
    """
    scan_max_progress_signal: pyqtSignal = pyqtSignal(int)  # ex: signal(255) - max value is 255 (addresses amount)

    scan_progress_update_signal: pyqtSignal = pyqtSignal(
        int)  # ex: signal(100) - how many addresses have finished being scanned (progress)

    scan_address_result_signal: pyqtSignal = pyqtSignal(Host)
    scan_address_no_longer_online_signal: pyqtSignal = pyqtSignal(str)  # Carries host IP addr that is no longer online

    scan_finished_signal: pyqtSignal = pyqtSignal(list, Host, float, int)
    # ex: signal([Host1, Host2..], float, 100, 10) - sent when the scan has finished -
    # Online Hosts list, scan time, scanned addresses amount, online hosts amount

    # Fingerprinting scan current progress value, max progress value, related host obj, scan_Str (full port / os detect)
    fp_scan_progress_signal: pyqtSignal = pyqtSignal(int, int, Host)
    fp_scan_finished_signal: pyqtSignal = pyqtSignal(Host)

    alert_pop_window_signal: pyqtSignal = pyqtSignal(str, str)

    # Modules signals:
    # Hosts connector
    new_host_connected_signal: pyqtSignal = pyqtSignal(tuple)  # Carries the socket addr (IP, port) of the new connected host
    new_message_signal: pyqtSignal = pyqtSignal(tuple)  # Carries the message host address (IP, port)
    connected_host_disconnected_signal: pyqtSignal = pyqtSignal(tuple)  # Carries the address of the disconnected host (IP, port)

    # Sniffer
    sniffer_traffic_signal: pyqtSignal = pyqtSignal(str)  # Carries the MAC address of the traffic host
    sniffer_high_traffic_signal: pyqtSignal = pyqtSignal(str)  # Carries the MAC address of the high traffic host
    sniffer_new_traffic_host_detected_signal: pyqtSignal = pyqtSignal(str)  # Carries the MAC address of the new traffic host

    # CONSTS:
    WELL_KNOWN_PORT_SCAN = "well-known-ps"
    FULL_PORT_SCAN = "full-ps"
    OS_DETECTION_SCAN = "os-detect"

    def __init__(self):
        """
        Initiates the network module.
        Loads the (sub)modules.
        """
        super().__init__()

        self.network_interfaces: list = discover_network_interfaces()
        self.selected_nic_index: int = -99

        self.scan_addresses: list = []
        self.stop_scan_flag = threading.Event()
        self.addresses_results_counter_lock = threading.Lock()

        self.router: Host | None = Host("", "", "", "", -1, "router")

        # Suppress scapy's warning messages
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        self.ip_to_host_obj_dict: Dict[str, Host] = {}
        self.mac_to_host_obj_dict: Dict[str, Host] = {}

        # Modules:
        # SCANNER
        self.scanner: NetworkScanner | None = None

        RED = '\033[91m'
        RESET = '\033[0m'

        # OS DETECTOR
        self.os_detector: OsDetector | None
        os_fp_data_path: str = r"src\module\packages\os_fp\data\os_fp_db.fp"
        if os.path.exists(os_fp_data_path):
            self.os_detector = OsDetector(os_fp_data_path)
        else:
            self.os_detector = None
            warning_message = "Could not find the data file for the OS detector. Please make sure it exists in it's folder.\n" \
                              "The analyzer will start without the OS detector."

            print(RED + warning_message + RESET)

        # MAC VENDOR LOOKUP
        self.mac_vendor_lookup: MacVendorLookup | None
        mac_vendor_lookup_data_path: str = r"src\module\packages\mac_vendor_lookup\data\mac_vendor_data.json"
        if os.path.exists(mac_vendor_lookup_data_path):
            self.mac_vendor_lookup = MacVendorLookup(mac_vendor_lookup_data_path)
        else:
            self.mac_vendor_lookup = None
            warning_message = "Could not find the data file for the MAC vendor lookup. Please make sure it exists in it's folder.\n" \
                              "The analyzer will start without the MAC vendor lookup module."

            print(RED + warning_message + RESET)

        # PORT SERVICE
        self.port_service_lookup: PortServiceLookup | None
        port_service_lookup_data_path: str = r"src\module\packages\ports_services_lookup\data\service-names-port-numbers.csv"
        if os.path.exists(port_service_lookup_data_path):
            self.port_service_lookup = PortServiceLookup(port_service_lookup_data_path)
        else:
            self.port_service_lookup = None
            warning_message = "Could not find the data file for the port service lookup. Please make sure it exists in it's folder.\n" \
                              "The analyzer will start without the ports services lookup module."

            print(RED + warning_message + RESET)

        # HOST CONNECTOR
        self.hosts_connector: AnalyzerHostsConnector = AnalyzerHostsConnector(self.new_host_connected_signal,
                                                                              self.new_message_signal,
                                                                              self.connected_host_disconnected_signal,
                                                                              self.alert_pop_window_signal)
        # SNIFFER
        self.sniffer: AnalyzerTrafficSniffer = AnalyzerTrafficSniffer(self.sniffer_traffic_signal,
                                                                      self.sniffer_high_traffic_signal,
                                                                      self.sniffer_new_traffic_host_detected_signal)

    def selected_interface(self, nic_index) -> None:
        """
        Function called when the user selects an interface from the dropbox.
        Sets the interface selected in the config and the addresses.
        :param nic_index: Given by the controller from the view module
        :return:
        """
        self.selected_nic_index = nic_index
        iface = self.network_interfaces[nic_index]
        self.scan_addresses = get_subnet_addresses_from_cidr(iface.cidr_notation)
        print(self.scan_addresses)
        conf.iface = iface.description

    def start_scanning_network(self, start_scan_addr: str, end_scan_addr: str, scan_method: str,
                               scan_inter: float, scan_timeout: float,
                               add_router_setting_on: bool, retrieve_hostname: bool, retrieve_res_time: bool) -> None:
        """
        Handles the network scan process.
        :param start_scan_addr: The starting IP address value in the starting IP entry.
        :param end_scan_addr: The end IP address value in the end IP entry.
        :param scan_method: The method of the scan (ARP / ICMP / Both).
        :param scan_inter: The interval between every packet of the scan (in seconds).
        :param scan_timeout: The timeout to wait for a response in the scan (in seconds).
        :param add_router_setting_on: Is the automatically add the router to the scan setting on.
        :param retrieve_hostname: Is the retrieve hostname of scanned host setting on.
        :param retrieve_res_time: Is the retrieve response time of scanned host setting on.
        :return:
        """
        # Scanning self.scan_addresses
        self.scan_addresses = get_addresses_between(start_scan_addr, end_scan_addr)
        # Router:
        net_router_addr = self.get_network_router_address()
        if add_router_setting_on:
            if net_router_addr == "N/A":
                self.alert_pop_window_signal.emit("WARNING",
                                                  "Couldn't discover the network's router address.\n"
                                                  "The scan will continue normally.")
            elif net_router_addr not in self.scan_addresses:
                self.scan_addresses.append(net_router_addr)

        # self.router = Host("", "", "", "", -1, "router")
        scan_start_time = time.time()
        print("SCANNING ADDRESSES:", self.scan_addresses)

        self.scanner = NetworkScanner(scan_addresses=self.scan_addresses, scan_method=scan_method,
                                      mac_vendor_lookup_module=self.mac_vendor_lookup,
                                      ip_to_host_obj_dict=self.ip_to_host_obj_dict,
                                      mac_to_host_obj_dict=self.mac_to_host_obj_dict,
                                      router_obj=self.router,
                                      iface=conf.iface,
                                      scan_progress_update_signal=self.scan_progress_update_signal,
                                      scan_max_progress_signal=self.scan_max_progress_signal,
                                      scan_host_finished_signal=self.scan_address_result_signal,
                                      scan_host_no_longer_online_signal=self.scan_address_no_longer_online_signal,
                                      retrieve_hostname=retrieve_hostname, retrieve_res_time=retrieve_res_time,
                                      timeout=scan_timeout, inter=scan_inter)

        scanned_amount = self.scanner.scan_network()  # (online_ips not in use)

        scan_took_time = time.time() - scan_start_time

        self.stop_scan_flag.clear()

        local_addr = self.network_interfaces[self.selected_nic_index].local_ip_address
        local_host = self.get_host_obj(local_addr)
        if local_host:
            local_host.type = "local_computer"
            print("I HAVE GOT THE LOCAL COMP!:", local_host)

        # If there is already a router host (was set in a previous scan) - no need to recreate it
        if not self.router.ip_address:
            print("NOT self.router.ip_address (network line 236)")
            # Scan for the network's router
            self.router = self.get_host_obj(net_router_addr)
            if self.router:
                self.router.type = "router"
                del self.ip_to_host_obj_dict[net_router_addr]
                print("I HAVE GOT THE ROUTER!:", self.router)

            if self.router is None:
                print("self.router IS NONE")
                # The value returned from get_host_obj() in None (not found)
                self.router = Host("", "", "", "", -1, "router")  # Set default empty router host value
        else:
            # If the router host obj already exists from previous scan, just remove it from the regular hosts dict.
            if net_router_addr in self.ip_to_host_obj_dict:
                del self.ip_to_host_obj_dict[net_router_addr]

        # Update the local ip addr for the hosts connector socket address
        self.hosts_connector.local_ip_addr = local_addr

        self.scan_finished_signal.emit(
            sorted([value for key, value in self.ip_to_host_obj_dict.items()], key=ip_to_int),
            self.router, scan_took_time, scanned_amount)

    def get_network_router_address(self) -> str:
        """
        Retrieves the IP address of the network's router.
        :return: The router IP address (str)
        """
        packet = IP(dst="8.8.8.8", ttl=1) / ICMP()

        response = sr1(packet, timeout=2, verbose=False, iface=conf.iface)
        if response:
            router_addr = response.src
        else:
            default_gateway = self.network_interfaces[self.selected_nic_index].default_gateway
            if default_gateway:
                router_addr = default_gateway
            else:
                router_addr = "N/A"
        return router_addr

    def get_host_obj(self, host_ip_addr: str = "", host_mac_addr: str = "") -> Host | None:
        """
        Returns the Host class object that represents a given IP / MAC address.
        :param host_ip_addr: The host's IP address.
        :param host_mac_addr: The host's MAC address.
        :return: The Host object, None if not found.
        """
        if host_ip_addr:
            matching_host = self.ip_to_host_obj_dict.get(host_ip_addr)
            if matching_host:
                return matching_host
        if host_mac_addr:
            matching_host = self.mac_to_host_obj_dict.get(host_mac_addr)
            if matching_host:
                return matching_host
        # Check if it's the router host
        if self.router:
            if host_ip_addr:
                if self.router.ip_address == host_ip_addr:
                    return self.router
            if host_mac_addr:
                if self.router.mac_address == host_mac_addr:
                    return self.router
        return None

    def run_fp_scan(self, host_obj: Host, scan_type, udp_setting_checked: bool, timeout: float) -> None:
        """
        Start a fingerprint scan for a host.
        :param host_obj: The Host object.
        :param scan_type: The scan type.
        :param udp_setting_checked: Is the scan for UDP ports setting checked.
        :param timeout: The timeout to wait for a response.
        :return: None
        """
        if scan_type == self.WELL_KNOWN_PORT_SCAN:
            print("RUNNING WELL KNOWN PORT SCAN")
            scan_str = "Well-known port scan"
            fp_scan_thread = threading.Thread(target=self.port_scan_handler, args=(host_obj, range(0, 1024),
                                                                                   udp_setting_checked, timeout))
        elif scan_type == self.FULL_PORT_SCAN:
            scan_str = "Full port scan"
            fp_scan_thread = threading.Thread(target=self.port_scan_handler, args=(host_obj, range(0, 65536),
                                                                                   udp_setting_checked, timeout))
        elif scan_type == self.OS_DETECTION_SCAN:
            if self.os_detector is None:
                return self.alert_pop_window_signal.emit("ERROR", "Missing the data file for the OS Detector module.\n"
                                                            "Please make sure it exists in the data folder "
                                                            "of the OS Detector and try again.")
            scan_str = "OS detection"
            fp_scan_thread = threading.Thread(target=self.run_os_detection_scan, args=(host_obj, timeout))

        host_obj.fp_scan_in_progress = True
        host_obj.current_fp_scan = scan_type
        host_obj.current_fp_scan_str = scan_str

        host_obj.fp_scan_progress_value = 0
        # Max progress is set by the specific fp scan function (port scan / os detect)
        # Progress updates timer is created by the CreateProgUpdatesTimerEvent
        host_obj.fp_scan_progress_lock = threading.Lock()
        host_obj.stop_fp_scan_flag = threading.Event()
        host_obj.stop_fp_scan_flag_lock = threading.Lock()

        fp_scan_thread.daemon = True
        fp_scan_thread.start()

    def port_scan_handler(self, target_host_obj: Host, ports_range: range, scan_udp: bool, timeout: float) -> None:
        """
        Handles the port scan fingerprint scan. (Runs in a thread)
        :param target_host_obj: The target Host object
        :param ports_range: The ports range to scan
        :param scan_udp: Should scan for UDP ports.
        :param timeout: The timeout to wait for a response from a port.
        :return:
        """
        port_scanner = PortScanner()
        self.create_host_fp_scans_prog_update_timer(host_obj=target_host_obj)
        port_scanner.run_port_scan(target_host_obj, ports_range, scan_udp, timeout)
        # Port scan has finished, sending the fp scan finished signal after 1 second to allow the prog bar to show 100%
        time.sleep(1)
        self.fp_scan_finished_signal.emit(target_host_obj)

    def run_os_detection_scan(self, target_host_obj: Host, timeout: float) -> None:
        """
        Handles the OS Detection fingerprint scan. (Runs in a thread)
        :param target_host_obj: The target Host object
        :param timeout: The timeout to wait for a response from a port.
        :return:
        """

        ports_set: set = set()
        open_ports = target_host_obj.open_ports
        if open_ports:
            if open_ports[0]:
                ports_set |= set(target_host_obj.open_ports[0])
            if open_ports[1]:
                ports_set |= set(target_host_obj.open_ports[1])
        ports_set |= set(self.os_detector.PORTS)

        target_host_obj.max_fp_scan_prog_value = len(ports_set)

        self.create_host_fp_scans_prog_update_timer(host_obj=target_host_obj)

        target_os: str = self.os_detector.detect_os(target_host_obj, ports_set, timeout)
        if target_os == "No match!":
            target_host_obj.operating_sys = "Not Available - No match found"
        elif target_os == "No open ports!":
            target_host_obj.operating_sys = "Not Available - No recognized open ports"
        else:
            target_host_obj.operating_sys = target_os if target_os else "Not Available"
        # OS Detection has finished, sending the fp scan finished signal after 1 second to allow the prog bar to show 100%
        time.sleep(1)
        self.fp_scan_finished_signal.emit(target_host_obj)

    def create_host_fp_scans_prog_update_timer(self, host_obj: Host) -> None:
        """
        Creates the host's fp scan progress update timer in the main thread using CreateProgUpdatesTimerEvent.
        :param host_obj: The Host object.
        :return:
        """
        if host_obj.fp_scan_in_progress and host_obj.information_window is not None:
            # Create progress updates timer only if the host has a fp scan running and the host's information window is opened
            QCoreApplication.instance().postEvent(self, CreateProgUpdatesTimerEvent(host_obj=host_obj))  # Trigger timer create event

    def send_fp_scan_prog_update(self, host_obj: Host) -> None:
        """
        Emits a signal that progress updates about a host's fingerprint scan.
        :param host_obj:
        :return:
        """
        if not host_obj.fp_scan_in_progress or host_obj.information_window is None:
            print("send_fp_scan_prog_update was called but host doesnt have a fp scan running or"
                  "host_obj info window is None - stopping the prog updates timer", host_obj.ip_address)
            return host_obj.fp_scan_progress_timer.stop()
        with host_obj.fp_scan_progress_lock:
            val = host_obj.fp_scan_progress_value
            self.fp_scan_progress_signal.emit(val, host_obj.max_fp_scan_prog_value, host_obj)
            if val == host_obj.max_fp_scan_prog_value:
                # Max progress value, stopping the progress updates timer
                host_obj.fp_scan_progress_timer.stop()

    def customEvent(self, event) -> None:
        """
        Receives the CreateProgUpdatesTimerEvent (custom) event and creates the progress updates timer in the main thread.
        :param event: The event received.
        :return: None
        """
        if isinstance(event, CreateProgUpdatesTimerEvent):
            host_obj = event.host_obj
            # Create the QTimer in the main thread
            timer = QTimer()
            host_obj.fp_scan_progress_timer = timer
            timer.timeout.connect(lambda: self.send_fp_scan_prog_update(host_obj))
            # .start(600)  # 0.6 seconds delay
            timer.start(1000)  # 1 second delay
            self.send_fp_scan_prog_update(host_obj)  # Send the 1st update without a delay.


class CreateProgUpdatesTimerEvent(QEvent):
    """
    The create progress updates timer custom event handled by AnalyzerNetwork.customEvent
    """
    def __init__(self, host_obj: Host):
        """
        Initiate the custom event's variable - event stores the Host object.
        :param host_obj: The Host object.
        """
        super().__init__(QEvent.User)  # User created (custom) event type
        self.host_obj = host_obj
