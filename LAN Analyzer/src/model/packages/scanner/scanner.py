"""
Author: Ofir Brovin.
This file contains the Network Scanner module of the LAN Analyzer project.
"""
from __future__ import annotations

import sys

if __name__ == '__main__':
    sys.exit("This file is part of the LAN Analyzer application and cannot be run independently")

import time

from threading import Thread, Lock

from typing import Dict, Tuple, List

from PyQt5.QtCore import pyqtSignal

from scapy.config import conf
from scapy.sendrecv import sniff
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether, ARP

from ..host import Host
from ..mac_vendor_lookup import MacVendorLookup
from ..util.network_functions import get_response_time, get_hostname


class NetworkScanner:
    """
    Network scanner.
    """
    NOT_SCANNED: int = 0
    NO_RESPONSE: int = 1
    ONLINE: int = 2
    OFFLINE: int = 3

    def __init__(self, scan_addresses: List[str], scan_method: str, mac_vendor_lookup_module: MacVendorLookup | None,
                 ip_to_host_obj_dict: dict, mac_to_host_obj_dict: dict, router_obj: Host, iface: str,
                 scan_progress_update_signal: pyqtSignal, scan_max_progress_signal: pyqtSignal,
                 scan_host_finished_signal: pyqtSignal, scan_host_no_longer_online_signal: pyqtSignal,
                 retrieve_hostname: bool, retrieve_res_time: bool,
                 timeout: float, inter: float):
        """
        Initiates the network scanner.
        :param scan_addresses: The list of IP addresses to scan.
        :param scan_method: The scan desired method (ARP / ICMP / BOTH)
        :param mac_vendor_lookup_module: The MAC vendor lookup module.
        :param ip_to_host_obj_dict: The dictionary to save ip: Host values. This dict is shared with the network module.
        :param mac_to_host_obj_dict: The dictionary to save MAC: Host values. This dict is shared with the network module.
        :param router_obj: The router Host object.
        :param iface: The network interface to scan on.
        :param scan_progress_update_signal: The network module's scan progress update signal.
        :param scan_max_progress_signal: The network module's scan max progress update signal.
        :param scan_host_finished_signal: The network module's host finished scan signal.
        :param scan_host_no_longer_online_signal: The network host no longer online signal.
        :param retrieve_hostname: Should retrieve hostname for every host.
        :param retrieve_res_time: Should retrieve res time for every host.
        :param timeout: The timeout to wait for a response from a host.
        :param inter: The interval to wait between each packet sends.
        """

        self.__scan_addresses: List[str] = scan_addresses
        self.__scan_method: str = scan_method
        self.__mac_vendor_lookup_module: MacVendorLookup | None = mac_vendor_lookup_module
        self.__iface: str = iface
        self.__timeout: float = timeout
        self.__inter: float = inter

        self.__scan_dict: Dict[str: int] = {}  # Map host to responded state ("0.0.0.0": 2 - responded - online)
        self.__scan_dict_lock: Lock = Lock()
        self.__start_times: Dict[str, float] = {}  # Map host (IP) to start time
        self.__ip_to_host_obj_dict: Dict[str, Host] = ip_to_host_obj_dict
        self.__mac_to_host_obj_dict: Dict[str, Host] = mac_to_host_obj_dict
        self.__router_obj = router_obj

        self.__scanned_amount: int = 0  # Tracks how many hosts were scanned (were sent a packet)
        self.__scan_progress_amount: int = 0
        self.__max_prog: int = len(self.__scan_addresses) * 2

        # This is used when the scan run is both ARP & ICMP to add to the value sent with
        # the signal to show the total progress of the scan
        self.__scan_progress_addition: int = 0

        self.__scan_progress_lock: Lock = Lock()
        self.__time_is_up: bool = False
        self.__time_up_lock: Lock = Lock()
        self.__stop_scan: bool = False
        self.__stop_scan_lock: Lock = Lock()

        # Signals
        self.__scan_progress_update_signal: pyqtSignal = scan_progress_update_signal
        self.__scan_max_progress_signal: pyqtSignal = scan_max_progress_signal
        self.__scan_host_finished_signal: pyqtSignal = scan_host_finished_signal
        self.__scan_host_no_longer_online_signal: pyqtSignal = scan_host_no_longer_online_signal

        # Further host info gather
        self.__retrieve_hostname = retrieve_hostname
        self.__retrieve_res_time = retrieve_res_time

    def _is_stop_scan_set(self) -> bool:
        """
        Checks if the stop scan var is set.
        :return: Is the stop scan var set or not.
        """
        with self.__stop_scan_lock:
            return self.__stop_scan

    def set_stop_scan(self, value: bool) -> None:
        """
        Sets the stop scan var value.
        :param value: The value to set to.
        :return: None
        """
        with self.__stop_scan_lock:
            self.__stop_scan = value

    def _is_time_up(self) -> bool:
        """
        Checks if the time is up var is set.
        :return: Is the time is up var set or not.
        """
        with self.__time_up_lock:
            return self.__time_is_up

    def _set_time_is_up(self, value: bool) -> None:
        """
        Sets the time is up var value.
        :param value: The value to set to.
        :return: None
        """
        with self.__time_up_lock:
            self.__time_is_up = value

    def scan_network(self) -> int:
        """
        Performs the network scan using the desired method.
        :return: The number of addresses that were scanned (sent a packet).
        """
        if self.__scan_method == "ARP":
            self.__scan_max_progress_signal.emit(self.__max_prog)
            return self._arp_scan()[1]  # Return the scanned amount (the list is for when scanning with both)
        elif self.__scan_method == "ICMP":
            self.__scan_max_progress_signal.emit(self.__max_prog)
            return self._ping_scan()
        elif self.__scan_method == "BOTH":
            self.__scan_max_progress_signal.emit(self.__max_prog * 2)
            return self._arp_and_ping_scan()

    def _arp_scan(self) -> Tuple[list, int]:
        """
        Performs the network scan using the ARP protocol.
        :return: A list of the responding IP addresses and the scanned (sent a packet) amount.
        """
        self.__scan_dict = {ip_addr: self.NOT_SCANNED for ip_addr in self.__scan_addresses}
        self.__start_times.clear()
        timeout = (self.__inter * len(self.__scan_addresses)) + 2 * self.__timeout
        # Sniff thread
        sniff_thread = Thread(target=sniff, kwargs={"prn": self._process_packet, "filter": "arp", "timeout": timeout,
                                                    "store": False})
        sniff_thread.daemon = True
        sniff_thread.start()
        # Managing responses thread
        monitor_thread = Thread(target=self._monitor_responses)
        monitor_thread.daemon = True
        monitor_thread.start()

        self._send_requests_packets(packets_type="ARP")

        monitor_thread.join()

        responding_hosts_ip_addrs = [ip_addr for (ip_addr, state) in self.__scan_dict.items() if state == self.ONLINE]
        print("Responding hosts: (ARP SCAN)")
        print(responding_hosts_ip_addrs)

        return responding_hosts_ip_addrs, self.__scanned_amount

    def _ping_scan(self) -> int:
        """
        Performs the network scan using the ICMP protocol.
        :return: The scanned (sent a packet) amount.
        """
        self.__scan_dict = {ip_addr: self.NOT_SCANNED for ip_addr in self.__scan_addresses}
        self.__start_times.clear()
        timeout = (self.__inter * len(self.__scan_addresses)) + 2 * self.__timeout

        # Sniff thread
        sniff_thread = Thread(target=sniff, kwargs={"prn": self._process_packet, "filter": "icmp", "timeout": timeout,
                                                    "store": False})
        sniff_thread.daemon = True
        sniff_thread.start()
        # Managing responses thread
        monitor_thread = Thread(target=self._monitor_responses)
        monitor_thread.daemon = True
        monitor_thread.start()

        self._send_requests_packets(packets_type="ICMP")

        monitor_thread.join()

        # self.scan_dict gets updated with hosts results

        return self.__scanned_amount

    def _arp_and_ping_scan(self) -> int:
        """
        Performs the network scan using both the ARP and ICMP protocols.
        :return: The scanned (sent a packet) amount.
        """
        arp_res_ips, arp_scanned_amount = self._arp_scan()
        self.__scan_progress_addition = self.__scan_progress_amount
        self.__scan_progress_amount = 0
        self.__scanned_amount = 0
        for ip in arp_res_ips:
            # Remove the responding IP addr from the scan addresses list - it was already scanned via ARP
            self.__scan_addresses.remove(ip)
            # Update scan progress
            with self.__scan_progress_lock:
                self.__scan_progress_amount += 2  # Add two to cover for sent progress and response progress
                self.__scan_progress_update_signal.emit(self.__scan_progress_amount)

        self._set_time_is_up(value=False)
        ping_scanned_amount = self._ping_scan()

        return max(arp_scanned_amount, ping_scanned_amount)

    def _send_requests_packets(self, packets_type: str) -> None:
        """
        Sending a request packet to every host in self.scan_addresses using the given protocol
        :param packets_type: The protocol to use (ARP / ICMP)
        :return: None
        """
        # Socket to send request packets
        sock = conf.L2socket(iface=self.__iface)
        # Send a request packet for each host ip addr
        for ip in self.__scan_addresses:
            # First set-up variables so that if the response is instant, all vars are ready
            with self.__scan_dict_lock:
                self.__scan_dict[ip] = self.NO_RESPONSE
                self.__start_times[ip] = time.time()  # Record start time for each host

            # Update progress - packet sent
            with self.__scan_progress_lock:
                self.__scan_progress_amount += 1
                self.__scan_progress_update_signal.emit(self.__scan_progress_addition + self.__scan_progress_amount)
                stop_scan_set: bool = self._is_stop_scan_set()
                if not stop_scan_set:
                    self.__scanned_amount += 1

            if stop_scan_set:
                # Stop scan set - don't actually send the packet
                continue
            # Now send the packet
            elif packets_type == "ARP":
                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
                sock.send(arp_request)
            elif packets_type == "ICMP":
                ping_request = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=ip) / ICMP()
                sock.send(ping_request)

            time.sleep(self.__inter)  # Interval

        # After finished sending all packets, wait for the set timeout, and after timeout expired - time is up.
        time.sleep(self.__timeout)
        self._set_time_is_up(value=True)

    def _process_packet(self, packet) -> None:
        """
        The scanner packet callback function that processes a response packet.
        :param packet: The packet received.
        :return: None
        """
        if ARP in packet and packet[ARP].op == 2:  # ARP response
            responder_ip = packet[ARP].psrc
            responder_mac = packet.hwsrc
            with self.__scan_dict_lock:
                if responder_ip in self.__scan_dict and self.__scan_dict[responder_ip] == self.NO_RESPONSE:
                    # The arp received is from a host within the scan that wasn't yet marked as online.
                    t = Thread(target=self._retrieve_online_host_information, args=(responder_ip, responder_mac))
                    t.daemon = True
                    t.start()

        if ICMP in packet and packet[ICMP].type == 0:  # ICMP Echo response
            responder_ip = packet[IP].src
            responder_mac = packet[Ether].src if Ether in packet else ""
            with self.__scan_dict_lock:
                if responder_ip in self.__scan_dict and self.__scan_dict[responder_ip] != self.ONLINE:
                    # The ping reply received is from a host within the scan that wasn't yet marked as online.
                    t = Thread(target=self._retrieve_online_host_information, args=(responder_ip, responder_mac))
                    t.daemon = True
                    t.start()

    def _retrieve_online_host_information(self, host_ip_addr: str, host_mac_addr: str) -> None:
        """
        Handles host has been discovered as responsive, retrieves further information if specified.
        :param host_ip_addr: The host IP address.
        :param host_mac_addr: The host MAC address.
        :return: None
        """
        with self.__scan_dict_lock:
            self.__scan_dict[host_ip_addr] = self.ONLINE
            if host_ip_addr in self.__start_times:
                del self.__start_times[host_ip_addr]
            # If the host is already in the dict, it means the scan is running after a scan was already run
            if host_ip_addr in self.__ip_to_host_obj_dict.keys():
                saved_mac_addr = self.__ip_to_host_obj_dict[host_ip_addr].mac_address
                if saved_mac_addr == host_mac_addr:
                    host = self.__ip_to_host_obj_dict[host_ip_addr]  # Work on the same host object
                else:
                    print("IP CONFLICT!!!\n"
                          f"Two MAC addresses: {saved_mac_addr}, {host_mac_addr}\n"
                          f"for the same IP: {host_ip_addr}")  # TODO
                    return
            elif host_ip_addr == self.__router_obj.ip_address:
                saved_router_mac_addr = self.__router_obj.mac_address
                if saved_router_mac_addr == host_mac_addr:
                    host = self.__router_obj  # Work on the same host (router) object
                else:
                    print("IP CONFLICT!!!\n"
                          f"Two MAC addresses: {saved_router_mac_addr}, {host_mac_addr}\n"
                          f"for the same IP (router): {host_ip_addr}")  # TODO
                    return
            else:
                mac_vendor = self.__mac_vendor_lookup_module.get_mac_vendor(host_mac_addr) if self.__mac_vendor_lookup_module is not None else ""
                host = Host(hostname="", ip_address=host_ip_addr, mac_address=host_mac_addr, mac_vendor=mac_vendor, response_time=-1)
        # Retrieve the information
        hostname_thread = None
        res_time_thread = None
        if self.__retrieve_hostname:
            hostname_thread = Thread(target=get_hostname, args=(host, self.__timeout))
            hostname_thread.daemon = True
            hostname_thread.start()
        if self.__retrieve_res_time:
            res_time_thread = Thread(target=get_response_time, args=(host, self.__timeout))
            res_time_thread.daemon = True
            res_time_thread.start()

        if hostname_thread:
            hostname_thread.join()
        if res_time_thread:
            res_time_thread.join()

        # Update dicts and progress - host online
        with self.__scan_dict_lock:
            self.__ip_to_host_obj_dict[host_ip_addr] = host
            self.__mac_to_host_obj_dict[host_mac_addr] = host

            self.__scan_progress_amount += 1
            self.__scan_progress_update_signal.emit(self.__scan_progress_addition + self.__scan_progress_amount)
            self.__scan_host_finished_signal.emit(host)

    def _monitor_responses(self) -> None:
        """
        Monitors the response states of scanned hosts.
        If the given timeout has passed from a host's packet send time, marks that host as offline.
        :return: None
        """
        while True:
            current_time = time.time()
            remove_addrs = []
            with self.__scan_dict_lock:
                for ip, start_time in self.__start_times.items():
                    if self._is_time_up() or self._is_stop_scan_set():
                        # If the scan time is up OR stop scan has been applied, mark all the remaining hosts as offline
                        elapsed_time = self.__timeout
                    else:
                        elapsed_time = current_time - start_time
                    if elapsed_time >= self.__timeout:
                        # ip timeout has come, setting its state to offline
                        self.__scan_dict[ip] = self.OFFLINE
                        remove_addrs.append(ip)
                        # Delete hosts object from ip and mac addresses dicts [if it's in] (host is no longer online)
                        if ip in self.__ip_to_host_obj_dict.keys():
                            # Means the host that was online before, is now offline
                            self.__scan_host_no_longer_online_signal.emit(ip)
                        # Update progress - host offline
                        with self.__scan_progress_lock:
                            self.__scan_progress_amount += 1
                            self.__scan_progress_update_signal.emit(self.__scan_progress_addition + self.__scan_progress_amount)
                for addr in remove_addrs:
                    del self.__start_times[addr]

            if self.__scan_progress_amount >= self.__max_prog:
                # The Scan has finished!
                return

            time.sleep(0.8)  # Check every 0.8 second
