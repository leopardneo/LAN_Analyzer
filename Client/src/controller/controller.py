"""
Author: Ofir Brovin.
This file is the controller of the LAN Analyzer host connector client.
"""
import socket

from typing import Tuple
from threading import Thread

from ..module import ConnectorClientNetwork
from ..view import ConnectorClientWindow


class HostConnectorClient:
    """
    LAN Analyzer host connector client.
    """
    def __init__(self, analyzer_address: Tuple[str, int]):
        """
        Initiates the connector client.
        :param analyzer_address: The LAN Analyzer listening address to connect to. [IP, port]
        """
        self.network_module = ConnectorClientNetwork(analyzer_address)
        self.view_window = ConnectorClientWindow()

        # Network signals connect
        self.network_module.message_received_signal.connect(lambda message_text, message_type: self.view_window.
                                                            add_message(message_text, message_type, True))
        self.network_module.analyzer_disconnected_signal.connect(self.view_window.analyzer_disconnected)

        # View connections
        self.view_window.send_tb.clicked.connect(self._handle_send_message)
        self.view_window.message_lineEdit.returnPressed.connect(self._handle_send_message)

        self.view_window.reconnect_button.clicked.connect(lambda: Thread(target=self._handle_reconnect).start())

    def _handle_send_message(self) -> None:
        """
        Sends a message to the LAN Analyzer.
        Function called when send button pressed or enter pressed in the lineEdit.
        :return: None
        """
        try:
            message_text = self.view_window.message_lineEdit.text()
            print(message_text)
            if not message_text:
                return
            self.network_module.send_message(message_text)
            self.view_window.message_lineEdit.clear()
            self.view_window.add_message(message_text, "REGULAR", False)
        except Exception as e:
            print("ERROR ON CLIENT HANDLE SEND MESSAGE:::", e)

    def _handle_reconnect(self) -> None:
        """
        Tries to re-establish the connection with the LAN Analyzer.
        :return: None
        """
        self.view_window.reconnecting_to_analyzer()
        try:
            self.network_module.connect_to_analyzer()
            self.view_window.analyzer_connected()
        except (ConnectionError, OSError, socket.timeout):
            self.view_window.analyzer_disconnected()
        except ValueError:
            # Raised if the connection was refused by the LAN Analyzer
            self.view_window.analyzer_not_accepting()
