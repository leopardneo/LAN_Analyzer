"""
Author: Ofir Brovin.
This file is the main runner script of the LAN Analyzer host connector client.
"""
import sys
import configparser

from typing import Tuple

from PyQt5.QtWidgets import QApplication

from src.controller import HostConnectorClient
from src.model.util.ip_address_functions import is_valid_ip_address, is_private_ip_address


def _get_analyzer_listening_address() -> Tuple[str, int]:
    """
    Gets the LAN Analyzer listening address (IP, port) from the config.ini file.
    :return: The address (IP, port)
    """
    config: configparser.ConfigParser = configparser.ConfigParser()
    config.read("config.ini")
    if not config.sections():
        raise FileNotFoundError("Could not find the config.ini file.\n"
                                "Please make sure it exists in the client folder and try again.")

    analyzer_ip_address = config["LAN Analyzer Admin Listening Address"]["ip"]
    analyzer_port = config["LAN Analyzer Admin Listening Address"]["port"]

    if not is_valid_ip_address(analyzer_ip_address):
        raise ValueError("The provided IP address in the config is not a valid IP address.")
    if not is_private_ip_address(analyzer_ip_address):
        raise ValueError("The provided IP address in the config is not a LAN address.\n"
                         "Please make sure you set the address to the correct LAN Analyzer listening address.")
    if not analyzer_port.isdigit() or not (0 < int(analyzer_port) <= 65535):
        raise ValueError("The provided port is not a valid port.\n"
                         "Please make sure you set the port to the correct LAN Analyzer listening port.")

    return analyzer_ip_address, int(analyzer_port)


if __name__ == '__main__':
    analyzer_address = _get_analyzer_listening_address()
    print("Starting Host Connector Client . . .")
    app = QApplication([])
    connector_client = HostConnectorClient(analyzer_address)
    sys.exit(app.exec_())
