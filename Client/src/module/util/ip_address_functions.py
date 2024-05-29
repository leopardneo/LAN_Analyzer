"""
Author: Ofir Brovin
This file is the network module utility file of the LAN Analyzer host connector client.
"""
import ipaddress


def is_valid_ip_address(ip_address: str) -> bool:
    """
    Checks if a given input is a valid IP address.
    :param ip_address: The input to check.
    :return: True if its valid address, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ip_address)
        return isinstance(ip, ipaddress.IPv4Address)
    except ValueError:
        return False


def is_private_ip_address(ip_address: str) -> bool:
    """
    Checks if a given IP address is private.
    :param ip_address: The IP address to check.
    :return: True if the address is private, False otherwise.
    """
    addr_list = list(map(int, ip_address.split(".")))

    # Check for private addresses
    if addr_list[0] == 10:
        return True
    if addr_list[0] == 172 and 16 <= addr_list[1] <= 31:
        return True
    if addr_list[0] == 192 and addr_list[1] == 168:
        return True
