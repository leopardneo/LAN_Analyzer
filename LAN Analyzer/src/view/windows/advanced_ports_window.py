"""
Author: Ofir Brovin.
This file contains the advanced ports information view window part of the LAN Analyzer application.
"""
from __future__ import annotations

from typing import List

from PyQt5 import QtCore
from PyQt5.uic import loadUi
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QWidget

from .help_window import HelpWindow


class AdvancedPortsInfoWindow(QWidget):
    """
    Advanced ports information view window class.
    """
    def __init__(self, total_open_ports_amount: int,
                 open_tcp_ports_and_services_list: List[str], open_tcp_ports_length: int,
                 closed_tcp_ports_and_services_list: List[str], closed_tcp_ports_length: int,
                 filtered_tcp_ports_and_services_list: List[str], filtered_tcp_ports_length: int,
                 udp_scanned: bool,
                 open_udp_ports_and_services_list: List[str], open_udp_ports_length: int,
                 closed_udp_ports_and_services_list: List[str], closed_udp_ports_length: int,
                 filtered_udp_ports_and_services_list: List[str], filtered_udp_ports_length: int):
        """
        Initiates the window - sets the values in the labels.
        :param total_open_ports_amount: Total open ports amount (TCP + UDP)
        :param open_tcp_ports_and_services_list: Open TCP ports with their service string list.
        :param open_tcp_ports_length: Open TCP ports amount.
        :param closed_tcp_ports_and_services_list: Closed TCP ports with their service string list. (<10)
        :param closed_tcp_ports_length: Closed TCP ports amount.
        :param filtered_tcp_ports_and_services_list: Filtered TCP ports with their service string list. (<10)
        :param filtered_tcp_ports_length: Filtered TCP ports amount.
        :param udp_scanned: Were UDP ports scanned (True / False).
        :param open_udp_ports_and_services_list: Open UDP ports with their service string list.
        :param open_udp_ports_length: Open UDP ports amount.
        :param closed_udp_ports_and_services_list: Closed UDP ports with their service string list. (<10)
        :param closed_udp_ports_length: Closed UDP ports amount.
        :param filtered_udp_ports_and_services_list: Filtered UDP ports with their service string list. (<10)
        :param filtered_udp_ports_length: Filtered UDP ports amount.
        """

        super().__init__()
        loadUi(r"src\view\windows\views\advanced_ports_information_window.ui", self)
        self.close_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.close_button.clicked.connect(self.close)

        self.ports_help_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.ports_help_tb.clicked.connect(self._show_ports_help)
        self.help_window: HelpWindow | None = None

        # Set-up information:
        self.total_open_ports_label.setText(f"Total Open Ports: {total_open_ports_amount}")
        # TCP
        # OPEN TCP PORTS
        self.open_tcp_ports_label.setText(
            f"{open_tcp_ports_length} Open TCP {'Port' if open_tcp_ports_length == 1 else 'Ports'}.")
        self.open_tcp_ports_services_label.setText("\n".join(open_tcp_ports_and_services_list))

        # CLOSED TCP PORTS
        self.closed_tcp_ports_label.setText(
            f"{closed_tcp_ports_length} Closed TCP {'Port' if closed_tcp_ports_length == 1 else 'Ports'}.")
        self.closed_tcp_ports_services_label.setText("\n".join(closed_tcp_ports_and_services_list))

        # FILTERED TCP PORTS
        self.filtered_tcp_ports_label.setText(
            f"{filtered_tcp_ports_length} Filtered TCP {'Port' if filtered_tcp_ports_length == 1 else 'Ports'}.")
        self.filtered_tcp_ports_services_label.setText("\n".join(filtered_tcp_ports_and_services_list))

        # UDP
        if udp_scanned:
            # OPEN UDP PORTS
            self.open_udp_ports_label.setText(
                f"{open_udp_ports_length} Open UDP {'Port' if open_udp_ports_length == 1 else 'Ports'}.")
            self.open_udp_ports_services_label.setText("\n".join(open_udp_ports_and_services_list))

            # CLOSED UDP PORTS
            self.closed_udp_ports_label.setText(
                f"{closed_udp_ports_length} Closed UDP {'Port' if closed_udp_ports_length == 1 else 'Ports'}.")
            self.closed_udp_ports_services_label.setText("\n".join(closed_udp_ports_and_services_list))

            # FILTERED UDP PORTS
            self.filtered_udp_ports_label.setText(
                f"{filtered_udp_ports_length} Filtered UDP {'Port' if filtered_udp_ports_length == 1 else 'Ports'}.")
            self.filtered_udp_ports_services_label.setText("\n".join(filtered_udp_ports_and_services_list))
        else:
            self.open_udp_ports_label.setText("-Not Scanned-")
            self.open_udp_ports_label.setDisabled(True)
            self.open_udp_ports_label.setAlignment(QtCore.Qt.AlignCenter)
            # Remove default values
            self.open_udp_ports_services_label.clear()
            self.open_udp_image.clear()
            self.closed_udp_ports_label.clear()
            self.closed_udp_ports_services_label.clear()
            self.closed_udp_image.clear()
            self.filtered_udp_ports_label.clear()
            self.filtered_udp_ports_services_label.clear()
            self.filtered_udp_image.clear()

    def _show_ports_help(self) -> None:
        """
        Opens the help window with the help message for the advanced ports information window.
        :return: None
        """
        help_text: str = "Here you can preview advanced information about the host's ports status.\n\n\n" \
                         "Open ports are ports that reply and accept the connection.\n" \
                         "Open ports are the most dangerous.\n" \
                         "Open ports offer services that are potentially\n" \
                         "vulnerable to attacks that exploit those services!\n\n" \
                         "Closed ports are ports that reply to a request but don't accept it (RST / ICMP Unreachable).\n" \
                         "Closed ports offer medium security.\n" \
                         "Closed ports reveal that the system is up, and might provide some additional\n" \
                         "fingerprinting information to potential intruders.\n\n" \
                         "Filtered ports are ports that do not reply to a request at all.\n" \
                         "Filtered ports are the best security level.\n" \
                         "Filtered ports do not respond to a requests at all, they don't appear to exist.\n" \
                         "It provides no information about the system or its existence (a.k.a. black hole).\n" \
                         "NOTE: The UDP protocol is not lossless and does not guarantee responses to all requests by design.\n" \
                         "Therefore, the lack of a response does not necessarily mean that a port is being filtered.\n" \
                         "If a port does not respond at all, it is reasonable to assume that the port might be filtered or simply unresponsive.\n"

        self.help_window = HelpWindow(help_text)
        self.help_window.show()
