"""
Author: Ofir Brovin.
This file contains the Port Service Lookup module of the LAN Analyzer application.
"""
import csv

from typing import List, Tuple, Dict


class PortServiceLookup:
    """
    LAN Analyzer Port Service Lookup module
    """
    def __init__(self, data_file_path: str):
        """
        Initiates the module.
        :param data_file_path: The path to the ports services information file.
        """
        self.__data_file_path = data_file_path
        self.__tcp_services: Dict[int, str]
        self.__udp_services: Dict[int, str]
        self.__tcp_services, self.__udp_services = self._parse_csv()

    @staticmethod
    def _parse_port_range(port_range: str) -> List[int]:
        """
        Converts ports range in string (10-20) to ports list.
        :param port_range: The port range in string.
        :return: List of the ports within the given range.
        """
        ports = []
        if port_range.strip():
            if '-' in port_range:
                start, end = port_range.split('-')
                start_port = int(start)
                end_port = int(end)
                ports.extend(range(start_port, end_port + 1))
            else:
                ports.append(int(port_range))
        return ports

    def _parse_csv(self) -> Tuple[Dict[int, str], Dict[int, str]]:
        """
        Parses the ports services csv information file.
        :return:
        """
        udp_services = {}
        tcp_services = {}
        with open(self.__data_file_path, 'r', encoding='utf-8') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            for row in csv_reader:
                port = row['Port Number']
                if not port:
                    continue
                protocol = row['Transport Protocol']
                service_name = row['Service Name']
                service_description = row['Description']
                port_list = self._parse_port_range(port)

                for p in port_list:
                    if protocol.upper() == 'TCP':
                        if p not in tcp_services:
                            tcp_services[p] = f"{service_name + ' - ' if service_name else ''}{service_description}"
                    elif protocol.upper() == 'UDP':
                        if p not in udp_services:
                            udp_services[p] = f"{service_name + ' - ' if service_name else ''}{service_description}"
        return tcp_services, udp_services

    def lookup_service(self, port, protocol) -> str:
        """
        Get the service related to the given port in the given protocol.
        :param port: The port.
        :param protocol: The protocol (TCP/ UDP)
        :return: The port's service. "Unknown" if not known.
        """
        port = int(port)
        if protocol.upper() == 'TCP':
            return self.__tcp_services.get(port, "Unknown")
        elif protocol.upper() == 'UDP':
            return self.__udp_services.get(port, "Unknown")
