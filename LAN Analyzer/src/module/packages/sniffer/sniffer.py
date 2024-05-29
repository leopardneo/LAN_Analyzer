"""
Author: Ofir Brovin.
This file is the Traffic Sniffer module of the LAN Analyzer application.
"""
from __future__ import annotations

import math
import time
import threading

from datetime import datetime
from typing import Dict, Tuple
from statistics import mean, stdev
from collections import defaultdict

from PyQt5.QtCore import pyqtSignal

from scapy.config import conf
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from scapy.all import sniff, Packet


class AnalyzerTrafficSniffer:
    """
    LAN Analyzer Traffic Sniffer.
    """
    def __init__(self, traffic_signal: pyqtSignal, high_traffic_signal: pyqtSignal,
                 new_traffic_host_detected_signal: pyqtSignal):
        """
        Initiates the LAN Analyzer Traffic Sniffer.
        :param traffic_signal: The network module traffic signal.
        :param high_traffic_signal: The network module high traffic signal.
        :param new_traffic_host_detected_signal: The network new traffic host detected signal.
        """

        self.__mac_addresses: dict.keys | None = None
        self.__mac_addresses_lock: threading.Lock = threading.Lock()
        self.__ip_addresses: dict.keys | None = None
        self.__ip_addresses_lock: threading.Lock = threading.Lock()

        self.__running: bool = False

        self.__sniff_thread: None | threading.Thread = None

        self.__packet_counts: defaultdict = defaultdict(int)
        self.__packet_counts_threshold: defaultdict = defaultdict(int)
        self.__suspicious_threshold: int = -1

        self.__hosts_incoming_traffic_packets_rate: defaultdict = defaultdict(int)
        self.__hosts_outgoing_traffic_packets_rate: defaultdict = defaultdict(int)
        self.hosts_datetime_to_packets_amount: Dict[str, Dict[datetime, Tuple[int, int]]] = defaultdict(lambda: defaultdict(lambda: (0, 0)))
        # ^ {"HOST MAC": {datetime: (in_packets_count, out_packets_count),..},..}

        self.__packets_store_lock: threading.Lock = threading.Lock()
        self.traffic_graphs_data_lock: threading.Lock = threading.Lock()

        self.__stop_sniffing_flag: threading.Event = threading.Event()
        self.__stop_sniffing_flag_lock: threading.Lock = threading.Lock()

        self.__traffic_signal: pyqtSignal = traffic_signal
        self.__high_traffic_signal: pyqtSignal = high_traffic_signal

        self.__new_traffic_host_detected_signal: pyqtSignal = new_traffic_host_detected_signal

        self.__address_to_last_signal_time: Dict[str: float] = {}

        # Set stores seen traffic MAC addresses
        self.__seen_mac_addresses: set = set()

    def set_mac_addresses(self, mac_address_value) -> None:
        """
        Updates the saved MAC addresses to a given value.
        :param mac_address_value: The value to set as the saved MAC addresses.
        :return: None
        """
        with self.__mac_addresses_lock:
            self.__mac_addresses = mac_address_value

    def set_ip_addresses(self, ip_address_value) -> None:
        """
        Updates the saved IP addresses to a given value
        :param ip_address_value: The value to set as the saved IP addresses.
        :return: None
        """
        with self.__ip_addresses_lock:
            self.__ip_addresses = ip_address_value

    def _in_saved_mac_addresses(self, mac_addr_to_check: str) -> bool:
        """
        Checks if a given MAC address is in the saved MAC addresses.
        :param mac_addr_to_check: The MAC address to check.
        :return: True if it's in the saved MAC addresses, False otherwise.
        """
        with self.__mac_addresses_lock:
            return self.__mac_addresses and mac_addr_to_check in self.__mac_addresses

    def _in_saved_ip_addresses(self, ip_addr_to_check: str) -> bool:
        """
        Checks if a given IP address is in the saved IP addresses.
        :param ip_addr_to_check: The IP address to check.
        :return: True if it's in the saved IP addresses, False otherwise.
        """
        with self.__ip_addresses_lock:
            return self.__ip_addresses and ip_addr_to_check in self.__ip_addresses

    def _packet_filter(self, packet: Packet) -> bool:
        """
        Function to use as filter function for the sniff function, to allow only packets that their src or dst address
        is an address that is within the saved addresses (MAC or IP).
        :param packet: The packet to filter.
        :return: True if the addresses in the packet exist in the saved MAC / IP addresses, False otherwise.
        """
        # TODO - currently the if checks also checks if the dst is included in the list but the signal emits only
        # the SRC mac, I am still allowing packets with only the dst in the lists to be sniffed in order for
        # the packets analyzation of each host in the traffic sniffer screen

        if Ether in packet:
            if self._in_saved_mac_addresses(packet[Ether].src) or self._in_saved_mac_addresses(packet[Ether].dst):
                return True

        if IP in packet:
            if self._in_saved_ip_addresses(packet[IP].src) or self._in_saved_ip_addresses(packet[IP].dst):
                return True

        return False

    def _is_stop_sniffing_flag_set(self) -> bool:
        """
        Checks if the stop sniffing flag event is set.
        :return: True if the stop sniffing flag is set, False otherwise.
        """
        with self.__stop_sniffing_flag_lock:
            return self.__stop_sniffing_flag.is_set()

    def start_sniffing(self) -> None:
        """
        Starts the sniffing threads.
        Starts the sniff function thread, the _calculate_threshold thread, the _send_traffic_updates thread,
        and the _save_date_to_packet_counts thread.
        :return: None
        """
        self.__sniff_thread = threading.Thread(target=sniff,
                                               kwargs={"prn": self._packet_callback,
                                                       "store": False, "iface": conf.iface,
                                                       "lfilter": lambda packet: self._packet_filter(packet),
                                                       "stop_filter": lambda x: self._is_stop_sniffing_flag_set()})

        threshold_thread = threading.Thread(target=self._calculate_threshold)
        updates_thread = threading.Thread(target=self._send_traffic_updates)
        save_graphs_data_thread = threading.Thread(target=self._save_date_to_packet_counts)

        self.__sniff_thread.daemon = True
        threshold_thread.daemon = True
        updates_thread.daemon = True
        save_graphs_data_thread.daemon = True

        self.__sniff_thread.start()
        threshold_thread.start()
        updates_thread.start()
        save_graphs_data_thread.start()

        self.__running = True

    def stop_sniffing(self) -> None:
        """
        Stops the sniffing process.
        Sets the stop flag and waits for the sniffer thread to stop.
        :return: None
        """
        if self.__running:
            with self.__stop_sniffing_flag_lock:
                self.__stop_sniffing_flag.set()
            self.__running = False
            while self.__sniff_thread.is_alive():
                pass  # Wait for the sniffer to terminate
                time.sleep(0.1)

    def _packet_callback(self, packet: Packet) -> None:
        """
        The callback function of the sniffer.
        Process a packet.
        :param packet: The sniffed packet
        :return: None
        """
        if Ether in packet:
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst

            src_mac_in_saved_mac_addresses: bool = self._in_saved_mac_addresses(src_mac)
            dst_mac_in_saved_mac_addresses: bool = self._in_saved_mac_addresses(dst_mac)
            # Check if the source or destination MAC is new
            if src_mac_in_saved_mac_addresses and src_mac not in self.__seen_mac_addresses:
                self._new_traffic_host_detected(src_mac)
            if dst_mac_in_saved_mac_addresses and dst_mac not in self.__seen_mac_addresses:
                self._new_traffic_host_detected(dst_mac)

            if src_mac_in_saved_mac_addresses or dst_mac_in_saved_mac_addresses:
                with self.__packets_store_lock:
                    if src_mac_in_saved_mac_addresses:
                        self.__packet_counts[src_mac] += 1
                        self.__packet_counts_threshold[src_mac] += 1  # Used for threshold calculation.
                        # Graphs data
                        self.__hosts_outgoing_traffic_packets_rate[src_mac] += 1  # Outgoing packet (sent by src_mac)
                    if dst_mac_in_saved_mac_addresses:
                        self.__hosts_incoming_traffic_packets_rate[dst_mac] += 1  # Incoming packet to the dst host

    def _new_traffic_host_detected(self, traffic_host_mac_addr: str) -> None:
        """
        Handles new traffic host detected.
        Emits the new traffic host detected signal and adds the host's addr to the seen addrs set.
        :param traffic_host_mac_addr: The host MAC address.
        :return: None
        """
        self.__new_traffic_host_detected_signal.emit(traffic_host_mac_addr)
        self.__seen_mac_addresses.add(traffic_host_mac_addr)

    def _calculate_threshold(self) -> None:
        """
        Calculates the packets per second threshold in order to flag hosts suspicious traffic rate (above the threshold)
        Runs in a thread. Calculates a new threshold every 10 seconds.
        :return: None
        """
        while True:
            with self.__stop_sniffing_flag_lock:
                if self.__stop_sniffing_flag.is_set():
                    break
            time.sleep(10)  # Sniff packets (in the background) for 10 seconds for analysis

            # Calculate the mean and standard deviation of packet counts
            packet_counts_per_second = [count / 10 for count in
                                        self.__packet_counts_threshold.values()]  # Convert counts to per second
            if len(packet_counts_per_second) < 2:
                if len(packet_counts_per_second) == 1:
                    mean_packet_count_per_second = packet_counts_per_second[0]
                    std_dev_packet_count_per_second = packet_counts_per_second[0]
                else:
                    # EMPTY (no data)
                    continue
            else:
                mean_packet_count_per_second = mean(packet_counts_per_second)
                std_dev_packet_count_per_second = stdev(packet_counts_per_second)

            # Set threshold as mean + 2 standard deviations
            thresh = math.ceil(mean_packet_count_per_second + 2 * std_dev_packet_count_per_second)
            self.__suspicious_threshold = math.ceil(thresh / 10) * 10  # Rounding up to 10 multi
            self.__packet_counts_threshold.clear()

    def _send_traffic_updates(self) -> None:
        """
        Responsible to send updates about hosts traffic detection as well as high traffic.
        Runs in a thread. Checks for updates every 1 second.
        :return: None
        """
        while True:
            with self.__stop_sniffing_flag_lock:
                if self.__stop_sniffing_flag.is_set():
                    break
            time.sleep(1)  # Send update every 1 second (matching the threshold calculation for 1 second)
            with self.__packets_store_lock:
                for src_mac, count in self.__packet_counts.items():
                    if not self._in_saved_mac_addresses(src_mac):
                        continue
                    if self.__suspicious_threshold != -1 and count > self.__suspicious_threshold:
                        # Emit the signal of high traffic
                        self.__high_traffic_signal.emit(src_mac)
                    else:
                        # Emit the signal of normal traffic
                        if src_mac in self.__address_to_last_signal_time and \
                                time.time() - self.__address_to_last_signal_time[src_mac] < 10:
                            # The last normal traffic update was less than 10 sec ago, no need to send again
                            continue
                        else:
                            self.__traffic_signal.emit(src_mac)
                            self.__address_to_last_signal_time[src_mac] = time.time()
                # Finished sending traffic updates - reset the stored packets counts
                self.__packet_counts.clear()

    def _save_date_to_packet_counts(self) -> None:
        """
        Responsible for saving information for the traffic graphs about a host's packets rate every second.
        :return: None
        """
        while True:
            with self.__stop_sniffing_flag_lock:
                if self.__stop_sniffing_flag.is_set():
                    break
            try:
                time.sleep(1)
                now = datetime.now()
                with self.__packets_store_lock:
                    for host in set(self.__hosts_incoming_traffic_packets_rate.keys()).union(
                            self.__hosts_outgoing_traffic_packets_rate.keys()):
                        incoming_count = self.__hosts_incoming_traffic_packets_rate.pop(host, 0)
                        outgoing_count = self.__hosts_outgoing_traffic_packets_rate.pop(host, 0)
                        with self.traffic_graphs_data_lock:
                            self.hosts_datetime_to_packets_amount[host][now] = (incoming_count, outgoing_count)

            except Exception as e:
                print("ERROR ON '_save_date_to_packet_counts' FUNCTION:", e)
