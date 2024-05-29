"""
Author: Ofir Brovin.
This file contains ip addresses functions as part of the LAN Analyzer project util module.
"""
import ipaddress

from typing import List


def get_subnet_addresses_from_cidr(network_address_w_subnet: str) -> List[str]:
    """
    Gets a list of all the addresses under a given network (in CIDR notation).
    :param network_address_w_subnet: The network CIDR.
    :return: A list of the network's addresses.
    """
    # Split network address and subnet
    network_addr, subnet = network_address_w_subnet.split("/")

    network_binary = ''.join(format(int(octet), '08b') for octet in network_addr.split('.'))

    subnet_bits_set = int(subnet)

    # Create a bitmask for the network portion
    bitmask = int(network_binary[:subnet_bits_set].ljust(32, '0'), 2)

    ip_addresses = []

    # Iterate through all possible host addresses
    for i in range(0, 2 ** (32 - subnet_bits_set)):
        # Calculate the host portion of the address
        host_portion = format(i, f'0{32 - subnet_bits_set}b')

        # Combine the network and host portions
        full_binary_address = bin(bitmask | int(host_portion, 2))[2:].zfill(32)

        # Convert the binary address back to decimal
        decimal_address = '.'.join(str(int(full_binary_address[i:i + 8], 2)) for i in range(0, 32, 8))

        ip_addresses.append(decimal_address)

    return ip_addresses


def get_addresses_between(start_ip: str, end_ip: str) -> List[str]:
    """
    Gets all the IP addresses in the range between two addresses.
    :param start_ip: Range start IP address.
    :param end_ip: Range end IP address.
    :return: A list of all the addresses of that range.
    """
    start_ip_obj = ipaddress.IPv4Address(start_ip)
    end_ip_obj = ipaddress.IPv4Address(end_ip)

    ip_range = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip_obj), int(end_ip_obj) + 1)]
    return ip_range


def ip_to_int(host) -> int:
    """
    Converts the IP address of a given host to an int representing it.
    :param host: The host object
    :return: The int representing its IP address.
    """
    octets = host.ip_address.split('.')
    integer_ip = 0
    for octet in octets:
        integer_ip = (integer_ip << 8) + int(octet)
    return integer_ip
