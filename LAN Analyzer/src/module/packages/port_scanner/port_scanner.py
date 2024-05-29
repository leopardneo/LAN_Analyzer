"""
Author: Ofir Brovin.
This file is the port scanner module of the LAN Analyzer application.
"""
import asyncio
from typing import Tuple, List

from scapy.layers.inet import IP, UDP, ICMP
from scapy.sendrecv import sr1

from ..host import Host


class PortScanner:
    """
    Port scanner for the LAN Analyzer network module
    """

    def __init__(self):
        """
        Initiates the port scanner.
        """
        self.tcp_scan_running: bool = False

    def run_port_scan(self, target_host_obj: Host, ports_range: range, scan_udp: bool, timeout: float) -> None:
        """
        Runs the port fp scan.
        Updates the host's ports variables after finished.
        :param target_host_obj: The target Host object
        :param ports_range: The ports range to scan.
        :param scan_udp: Should scan UDP (True / False)
        :param timeout: Timeout to wait for response from a port.
        :return: None
        """
        print(f"STARTING PORT SCANNING ({target_host_obj.ip_address})", scan_udp)

        target_host_obj.max_fp_scan_prog_value = len(ports_range) * (2 if scan_udp else 1)

        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        loop = asyncio.new_event_loop()

        tcp_future = loop.create_task(self._tcp_port_scan_async(target_host_obj, ports_range, timeout))
        if scan_udp:
            udp_future = loop.create_task(self._udp_port_scan(target_host_obj, ports_range, timeout))
        else:
            udp_future = asyncio.sleep(0)

        loop.run_until_complete(asyncio.gather(tcp_future, udp_future))

        open_tcp_ports, closed_tcp_ports, filtered_tcp_ports, last_tcp_port_scanned = tcp_future.result()
        if scan_udp:
            open_udp_ports, closed_udp_ports, filtered_udp_ports, last_udp_port_scanned = udp_future.result()
        else:
            open_udp_ports, closed_udp_ports, filtered_udp_ports, last_udp_port_scanned = [], [], [], 0

        # This will execute only when both of the scans futures are finished
        target_host_obj.scanned_ports = range(0,
                                              max(last_tcp_port_scanned, last_udp_port_scanned) + 1)  # Include the last
        target_host_obj.open_ports = open_tcp_ports, open_udp_ports
        target_host_obj.closed_ports = closed_tcp_ports, closed_udp_ports
        target_host_obj.filtered_ports = filtered_tcp_ports, filtered_udp_ports
        print(f"({target_host_obj.ip_address}) FINISHED PORT SCAN!", target_host_obj)
        # Analyzing the port scan results:
        all_open_ports_set = set(open_tcp_ports) | set(open_udp_ports)
        # Check for printer ports
        common_printer_ports = [35, 92, 515, 631, 1392, 3396, 3910, 3911]  # Based on information from IANA
        if any(port in all_open_ports_set for port in common_printer_ports):
            target_host_obj.type = "printer"

    @staticmethod
    def _chunked_ports(ports_range: range, chunk_size: int):
        """
        Creates a generator which divides the ports into chunks to send SYN request concurrently.
        :param ports_range: The ports full range to divide.
        :param chunk_size: Each chunk size.
        :return:
        """
        for i in range(0, len(ports_range), chunk_size):
            yield ports_range[i:i + chunk_size]

    @staticmethod
    async def _check_tcp_port(target_ip_addr: str, port: int, timeout: float) -> Tuple[int, str]:
        """
        Checks the status of a TCP port. (Open / Closed / Filtered)
        :param target_ip_addr: The target IP address.
        :param port: The target port number.
        :param timeout: The timeout in seconds to wait for a response from the port.
        :return: [Port, Str describing the port's status (open / closed / filtered)]
        """
        conn = asyncio.open_connection(target_ip_addr, port)
        try:
            _, writer = await asyncio.wait_for(conn, timeout)
            writer.close()
            await writer.wait_closed()
            return port, "open"
        except (asyncio.TimeoutError, ConnectionRefusedError):
            return port, "closed"
        except OSError:
            return port, "filtered"

    async def _tcp_port_scan_async(self, target_host_obj, ports: range, timeout: float) -> \
            Tuple[List[int], List[int], List[int], int]:
        """
        Performs the TCP scan.
        :param target_host_obj: The target Host object
        :param ports: The port range to scan
        :param timeout: The timeout in seconds to wait for a response from a port.
        :return: List of open ports, closed_ports, filtered_ports and the last_scanned_port.
        """
        open_ports: List[int] = []
        closed_ports: List[int] = []
        filtered_ports: List[int] = []
        self.tcp_scan_running = True

        last_scanned_port: int = 0
        target_ip_addr = target_host_obj.ip_address

        for chunk in self._chunked_ports(ports, chunk_size=100):
            tasks = []
            for port in chunk:
                with target_host_obj.stop_fp_scan_flag_lock:
                    if target_host_obj.stop_fp_scan_flag.is_set():
                        with target_host_obj.fp_scan_progress_lock:
                            target_host_obj.fp_scan_progress_value += 1
                        continue

                tasks.append(self._check_tcp_port(target_ip_addr, port, timeout))

            results = await asyncio.gather(*tasks)

            for port, status in results:
                last_scanned_port = port
                if status == "open":
                    open_ports.append(port)
                elif status == "closed":
                    closed_ports.append(port)
                else:
                    filtered_ports.append(port)

                with target_host_obj.fp_scan_progress_lock:
                    target_host_obj.fp_scan_progress_value += 1

        # print(f"({target_ip_addr}) OPEN TCP PORTS:", open_ports)
        self.tcp_scan_running = False
        return open_ports, closed_ports, filtered_ports, last_scanned_port

    async def _udp_port_scan(self, target_host_obj: Host, ports, timeout: float) \
            -> Tuple[List[int], List[int], List[int], int]:
        """
        Performs the UDP scan.
        :param target_host_obj: The target Host object
        :param ports: The port range to scan
        :param timeout: The timeout in seconds to wait for a response from a port.
        :return: List of open ports, closed_ports, filtered_ports and the last_scanned_port.
        """
        open_ports: List[int] = []
        closed_ports: List[int] = []
        filtered_ports: List[int] = []

        last_scanned_port: int = 0
        target_ip_addr = target_host_obj.ip_address
        udp_ports_scanned_in_a_row: float = 0
        for port in ports:
            with target_host_obj.stop_fp_scan_flag_lock:
                if target_host_obj.stop_fp_scan_flag.is_set():
                    # If the stop fp scan flag is set - send apply progress and continue
                    with target_host_obj.fp_scan_progress_lock:
                        target_host_obj.fp_scan_progress_value += 1
                    continue

            response = sr1(IP(dst=target_ip_addr) / UDP(dport=port), timeout=timeout, verbose=False)
            with target_host_obj.fp_scan_progress_lock:
                target_host_obj.fp_scan_progress_value += 1
            last_scanned_port = port
            if response:
                # Check if the response is an ICMP Port Unreachable message
                if response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code == 3:
                    closed_ports.append(port)  # Port is closed
                else:
                    open_ports.append(port)
                udp_ports_scanned_in_a_row += 0.5  # Add only 0.5 because if the host is sending response
                # packets, scanning the ports will be faster rather than when it's not sending (timeout waiting)
            else:
                filtered_ports.append(port)  # No response received - port is closed / filtered!
                udp_ports_scanned_in_a_row += 1

            if self.tcp_scan_running and udp_ports_scanned_in_a_row >= 3:
                # print("SCANNED 3 UDP PORTS IN A ROW! SLEEPING FOR 5 SECONDS TO ALLOW TCP")
                udp_ports_scanned_in_a_row = 0
                await asyncio.sleep(5)  # Give time for TCP scan to run

        # print("OPEN UDP PORTS:", open_ports)
        # print("CLOSED UDP PORTS:", closed_ports)
        # print("FILTERED UDP PORTS:", filtered_ports)
        return open_ports, closed_ports, filtered_ports, last_scanned_port
