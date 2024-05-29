"""
Author: Ofir Brovin.
This file contains network functions as part of the LAN Analyzer project util module.
"""
from __future__ import annotations

import re
import socket
import subprocess

from ..host import Host


def get_response_time(host_obj: Host, timeout: int) -> None:
    """
    Gets the response time (latency) of a host.
    Sets the Host's object response_time attribute. (-1 if couldn't retrieve)
    :param host_obj: The host's object.
    :param timeout: The timeout of the ping packets (in seconds)
    :return: None
    """
    try:
        output, _ = subprocess.Popen(["ping", "-4", "-w", str(timeout), host_obj.ip_address],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     shell=True, text=True).communicate()

        match = re.search(r"Average = (\d+)ms", output)
        if match:
            host_obj.response_time = int(match.group(1))
        else:
            host_obj.response_time = -1
    except Exception as e:
        print(f"Error getting response time for {host_obj.ip_address}: {e}")
        host_obj.response_time = -1


def get_hostname(host_obj: Host, timeout: int) -> None:
    """
    Gets the hostname of a host.
    Sets the Host's object hostname attribute. (Empty string if couldn't retrieve)
    :param host_obj: The host's object.
    :param timeout: The timeout of the retrieve hostname process (in seconds).
    :return: None
    """
    socket.setdefaulttimeout(timeout)
    try:
        host_obj.hostname = socket.gethostbyaddr(host_obj.ip_address)[0]
    except socket.herror:
        host_obj.hostname = ""
