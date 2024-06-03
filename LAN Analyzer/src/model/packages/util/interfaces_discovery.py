"""
Author: Ofir Brovin.
This file contains interfaces (NICs) discovery functions as part of the LAN Analyzer project util module.
"""
import re
import subprocess

from typing import List, Dict

from dataclasses import dataclass


@dataclass
class Interface:
    """
    Interface representation class
    """
    name: str
    mac_address: str
    local_ip_address: str
    subnet_mask: str
    cidr_notation: str
    description: str
    default_gateway: str


def discover_network_interfaces() -> List[Interface]:
    """
    Uses subprocess to retrieve installed NICs and regarding information.
    :return: A list of available network interfaces as Interface objects.
    """

    wmic_output, _ = subprocess.Popen("wmic nic get Name, Installed, NetConnectionStatus, MACAddress",
                                      shell=True,
                                      stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,
                                      stdin=subprocess.PIPE).communicate()

    mac_to_desc: Dict[str: str] = {}
    # Find connected nics and add to mac to name dict
    for i, nic_line in enumerate(wmic_output.split(b"\r\r\n")):
        nic_line = nic_line.strip()
        if i == 0:
            continue
        if not nic_line.endswith(b"2"):
            continue
        if not nic_line.startswith(b"TRUE"):
            continue
        mac_search = re.search(rb'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', nic_line)
        if not mac_search:
            continue
        mac_result = mac_search.group()
        name = nic_line[nic_line.find(mac_result) + len(mac_result): -1].strip().decode("ISO-8859-1", errors="replace")
        # Add to dict
        mac_to_desc[mac_result.decode("ISO-8859-1", errors="replace").replace("-", ":")] = name

    output, _ = subprocess.Popen("ipconfig /all",
                                 shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 stdin=subprocess.PIPE).communicate()

    interfaces_list: list = list()

    output = output[output.find(b"\r\n\r\n") + 4:]
    output = output[output.find(b"\r\n\r\n") + 4:]

    ipv4_pattern = rb"(?:\d{1,3}\.){3}\d{1,3}"
    ipv6_pattern = rb"[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,7}"

    # Loop over NICs
    while output.find(b"\r\n\r\n") != -1:
        name: str = output[0:output.find(b":")].decode("ISO-8859-1", errors="replace").replace("�", "").replace("?", "").strip()  # Interface name
        # Interface physical address
        phys_addr_search: re.search = re.search(rb'^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}',
                                                output[output.find(b"Physical Address") + 36:])
        phys_addr = phys_addr_search.group().decode("ISO-8859-1", errors="replace").replace("-", ":") if phys_addr_search else ""
        # Interface assigned IP address
        if output.find(b"IPv4 Address") != -1 and (output[output.find(b"\r\n\r\n") + 4:].find(b"IPv4 Address") <
                                                   output[output.find(b"\r\n\r\n") + 4:].find(b"\r\n\r\n") or
                                                   output[output.find(b"\r\n\r\n") + 4:].find(b"\r\n\r\n") == -1):
            ip_addr_search: re.search = re.search(ipv4_pattern, output[output.find(b"IPv4 Address") + 36:])
            ip_addr = ip_addr_search.group().decode("ISO-8859-1", errors="replace") if ip_addr_search else ""
        else:
            ip_addr = ""
        # Interface subnet mask
        if output.find(b"Subnet Mask") != -1 and (output[output.find(b"\r\n\r\n") + 4:].find(b"Subnet Mask") <
                                                  output[output.find(b"\r\n\r\n") + 4:].find(b"\r\n\r\n") or
                                                  output[output.find(b"\r\n\r\n") + 4:].find(b"\r\n\r\n") == -1):
            subnet_search: re.search = re.search(ipv4_pattern, output[output.find(b"Subnet Mask") + 36:])
            subnet_mask = subnet_search.group().decode("ISO-8859-1", errors="replace") if subnet_search else ""
        else:
            subnet_mask = ""
        # Interface default gateway
        if output.find(b"Default Gateway") != -1 and (output[output.find(b"\r\n\r\n") + 4:].find(b"Default Gateway") <
                                                      output[output.find(b"\r\n\r\n") + 4:].find(b"\r\n\r\n") or
                                                      output[output.find(b"\r\n\r\n") + 4:].find(b"\r\n\r\n") == -1):

            combined_pattern = b"(?:%s)?\\s*(%s)" % (ipv6_pattern, ipv4_pattern)
            gateway_search: re.search = re.search(combined_pattern, output[output.find(b"Default Gateway") + 36:])
            default_gateway = gateway_search.group().decode("ISO-8859-1", errors="replace").strip() if gateway_search else ""
        else:
            default_gateway = ""

        if name and phys_addr and ip_addr and subnet_mask:
            iface = Interface(name, phys_addr, ip_addr, subnet_mask, ip_and_subnet_to_cidr(ip_addr, subnet_mask),
                              mac_to_desc[phys_addr], default_gateway)
            interfaces_list.append(iface)

        output = output[output.find(b"\r\n\r\n") + 4:]
        output = output[output.find(b"\r\n\r\n") + 4:]

    return interfaces_list


def ip_and_subnet_to_cidr(ip_address: str, subnet: str) -> str:
    """
    Converts IP address and subnet mask to cidr notation
    :param ip_address:
    :param subnet:
    :return: CIDR notation of the network address and subnet mask
    """
    ip_octs = ip_address.split(".")
    subnet_octs = subnet.split(".")

    network_address: list = []
    tot_bits: int = 0

    for i in range(4):
        ip_bits = bin(int(ip_octs[i]))[2:].zfill(8)
        subnet_bits = bin(int(subnet_octs[i]))[2:].zfill(8)

        network_bits = "".join(str(int(a) & int(b)) for a, b in zip(ip_bits, subnet_bits))
        network_address.append(str(int(network_bits, 2)))
        tot_bits += subnet_bits.count("1")

    cidr_notation = f"{'.'.join(network_address)}/{tot_bits}"
    return cidr_notation
