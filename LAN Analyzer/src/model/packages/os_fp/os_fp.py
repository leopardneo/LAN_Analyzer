"""
Author: Ofir Brovin.
This file contains the OS Fingerprint Detector module of the LAN Analyzer application.
"""
from __future__ import annotations

from typing import List

from scapy.sendrecv import sr1
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP

from ..host import Host


class OsDetector:
    """
    LAN Analyzer OS Detector module
    """
    PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 626, 3389, 49152, 62078]

    SYN_ACK_RANGE: tuple = (360, 544)

    # SYN_RANGE: tuple = (360 ,534)  # TODO

    def __init__(self, data_file_path: str):
        """
        Initiates the module.
        :param data_file_path: The path to the os fp information file.
        """
        with open(data_file_path) as fp_file:
            self.__fp_database: List[str] = fp_file.readlines()

    def detect_os(self, target_host: Host, ports: set, timeout: float) -> str:
        """
        Tries to detect the Operating System of a given host.
        :param target_host: The target host object.
        :param ports: The ports to use to try and connect to the host to detect OS.
        :param timeout: The time to wait for a response from a port.
        :return: A string representing the target's OS.
        "No match!" if no match has been found, "No open ports!" if no open ports were found
        """

        found_open_port: bool = False
        value = 0
        for port in ports:
            value += 1
            with target_host.fp_scan_progress_lock:
                target_host.fp_scan_progress_value = value
            with target_host.stop_fp_scan_flag_lock:
                if target_host.stop_fp_scan_flag.is_set():
                    # If stop fp scan flag is set - progress already updated - just continue
                    continue
            tcp_res = get_tcp_syn_response(target_host, port, timeout)
            if tcp_res:
                if tcp_res[TCP].flags == 0x14:
                    # RST
                    # print("GOT RST")
                    continue
                if tcp_res[TCP].flags == 0x12:
                    found_open_port = True
                    # SYN/ACK
                    # print("GOT SA")
                    sig: str = get_packet_sig(tcp_res)
                    # print("THIS IS THE SIG I CREATED:::", sig)
                    os_label = self.search_sig_in_db(sig, "SA")
                    # print("OS_LABEL:", os_label)
                    if os_label:
                        os_label = os_label.split(":")
                        target_host.fp_scan_progress_value = target_host.max_fp_scan_prog_value
                        return f"{os_label[2]} {os_label[3]}"
                elif tcp_res[TCP].flags == 0x10:
                    # ACK  TODO
                    # print("GOT ACK")
                    sig: str = get_packet_sig(tcp_res)
                    self.search_sig_in_db(sig, "A")
        else:
            if found_open_port:
                print("DID NOT FIND INFO ABOUT OS IN THE DB!")
                return "No match!"
            else:
                print("COULD NOT FIND THE OS OF THE HOST AS NO OPEN PORTS WERE FOUND!")
                return "No open ports!"

    def search_sig_in_db(self, signature: str, sig_type: str) -> str:
        """
        Searches for an os label match to the signature in the fp database.
        :param signature: The signature to look for
        :param sig_type: Signature type (ACK / SYN_ACK)
        :return: The label of the OS matching the signature (empty string if not found)
        """
        if sig_type == "SA":
            # SYN/ACK
            last_label: str = ""
            for line in self.__fp_database[self.SYN_ACK_RANGE[0]: self.SYN_ACK_RANGE[1]]:
                line = line.strip()
                if line.startswith("label"):
                    last_label = line.split(" = ")[1]  # Get the actual label
                elif line.startswith("sig"):
                    sig: str = line.split(" = ")[1].strip()
                    if signatures_match(signature, sig):
                        # print("FOUND A MATCH ON LINE:", line, "!", last_label)
                        return last_label
            return ""
        elif sig_type == "A":
            # ACK
            pass


def get_tcp_syn_response(target_host: Host, port_num: int, timeout: float) -> Packet | None:
    """
    Sends a TCP SYN request to a host and returns its response.
    :param target_host: The target Host object.
    :param port_num: The port to send the request to.
    :param timeout: The timeout to wait for a response from the port.
    :return: The response packet or None if no response.
    """
    ip_addr = target_host.ip_address
    syn_packet = IP(dst=ip_addr) / TCP(dport=port_num, flags="S")
    response = sr1(syn_packet, timeout=timeout, verbose=False)

    return response


def get_packet_sig(packet: Packet) -> str:
    """
    Creates a signature based on the given packet.
    :param packet: The packet (TCP SYN/ACK).
    :return: The created signature.
    """
    ip_layer = packet[IP]
    ip_version = ip_layer.version
    ttl = ip_layer.ttl
    olen = len(ip_layer.options)

    tcp_layer = packet[TCP]

    mss = [opt for opt in tcp_layer.options if opt[0] == "MSS"][0][1]

    wsize = tcp_layer.window

    scale = tcp_layer.options[1][1] if len(tcp_layer.options) > 1 and tcp_layer.options[0][0] == 'WScale' else 0

    # TCP options layout (olayout) ('mss,sok,ts,nop,ws,nop,nop,sackOK')
    olayout = (",".join([opt[0] for opt in tcp_layer.options])).lower()

    quirks = extract_quirks(packet)

    # PCLASS
    pclass = "+" if len(tcp_layer.payload) > 0 else "0"

    return ":".join(map(str, [ip_version, ttl, olen, mss, f"{wsize},{scale}", olayout, quirks, pclass]))  # SIG


def extract_quirks(packet: Packet) -> str:
    """
    Extracts quirks from the packet.
    :param packet: The packet (TCP SYN/ACK).
    :return: The quirks of the packet.
    """
    quirks = []
    ip_layer = packet.getlayer(IP)
    tcp_layer = packet.getlayer(TCP)

    # IP
    if ip_layer:
        if ip_layer.flags.DF:  # DF flag set
            quirks.append("df")
        if ip_layer.flags.MF and ip_layer.id != 0:  # More Fragments flag set and IP ID non-zero
            quirks.append("id+")
        if not ip_layer.flags.DF and ip_layer.id == 0:  # Don't Fragment flag not set and IP ID zero
            quirks.append("id-")
        if ip_layer.proto == 6 and ('ECN' in ip_layer.flags or 'CE' in ip_layer.flags):  # ECN support
            quirks.append("ecn")

    # TCP
    if tcp_layer:
        if tcp_layer.seq == 0:  # TCP sequence number zero
            quirks.append("seq-")
        if tcp_layer.ack != 0 and 'A' not in tcp_layer.flags:  # TCP ACK number non-zero but ACK flag not set
            quirks.append("ack+")
        if tcp_layer.ack == 0 and 'A' in tcp_layer.flags:  # TCP ACK number zero but ACK flag set
            quirks.append("ack-")
        if tcp_layer.urgptr != 0 and 'U' not in tcp_layer.flags:  # TCP URG pointer non-zero but URG flag not set
            quirks.append("uptr+")
        if 'U' in tcp_layer.flags:  # TCP URG flag used
            quirks.append("urgf+")
        if 'P' in tcp_layer.flags:  # TCP PUSH flag used
            quirks.append("pushf+")
        if tcp_layer.options and tcp_layer.options[-1][0] != "NOP":  # Trailing non-zero data in TCP options
            quirks.append("opt+")

    return ",".join(quirks)


def signatures_match(sig1: str, sig2: str):
    """
    Compares two signatures.
    :param sig1: The created signature.
    :param sig2: The signature from the db to compare to.
    :return: True if the signatures match, False otherwise.
    """
    sig1 = sig1.split(":")
    sig2 = sig2.split(":")
    # Loop on each element of the signature
    for i in range(len(sig1)):
        if sig1[i] != sig2[i] and sig2[i] != "*":
            return False
    return True
