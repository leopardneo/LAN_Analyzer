"""
Author: Ofir Brovin.
This file contains the MAC Vendor Lookup module of the LAN Analyzer application.
"""
import json

from typing import Dict


class MacVendorLookup:
    """
    LAN Analyzer MAC Vendor Lookup module
    """
    def __init__(self, data_file_path: str):
        """
        Initiates the module.
        :param data_file_path: The path to the mac vendor information file.
        """
        self.__data_file_path = data_file_path
        self._load_data()

    def _load_data(self) -> None:
        """
        Loads the data from the file into the self.mac_vendor_data variable.
        :return: None
        """
        with open(self.__data_file_path, "r", encoding="utf-8") as mac_vendor_file:
            self.__mac_vendor_data: Dict[str, str] = json.load(mac_vendor_file)

    def get_mac_vendor(self, mac_address: str) -> str:
        """
        Get the MAC vendor of a given MAC address.
        Used by the network scanner module in _retrieve_online_host_information().
        :param mac_address: The MAC address
        :return: The MAC vendor. Empty string if not found.
        """
        if not mac_address:
            return ""
        mac_prefix = mac_address.replace(":", "-").upper()[0: 8]
        return self.__mac_vendor_data.get(mac_prefix, "")
