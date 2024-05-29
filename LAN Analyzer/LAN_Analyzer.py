"""
Author: Ofir Brovin.
This file is the main script that runs the LAN Analyzer project.
"""
import sys
import configparser

from PyQt5.QtWidgets import QApplication

from src.controller import LanAnalyzer


class Settings:
    """
    LAN Analyzer settings class, used to apply the settings from the config.ini file to the LAN Analyzer when run.
    """
    DEFAULT_SETTINGS = {
        "Scanner Settings": {
            "interval": 0.1,
            "timeout": 2.5,
            "method": "ARP",
            "retrieve hostname": True,
            "retrieve latency": False,
            "automatically add router": True
        },
        "Fingerprint Settings": {
            "run well known port scan": False,
            "run full port scan": False,
            "run os detection scan": False,
            "scan udp ports": False
        }
    }

    def __init__(self, settings_file_path: str):
        """
        Initiates the settings.
        If the config.ini doesn't exist or has invalid values, creates it with the default values.
        :param settings_file_path: The path to the config.ini file
        """
        self.settings_file_path: str = settings_file_path
        self.settings: configparser.ConfigParser = configparser.ConfigParser()

        try:
            self.settings.read(self.settings_file_path)
            if not self.settings.sections():
                raise FileNotFoundError
            if not self.are_settings_valid():
                raise ValueError
        except (FileNotFoundError, ValueError):
            # Create the file if missing or invalid
            self.create_default_settings_file()
            self.settings.read(self.settings_file_path)

    def create_default_settings_file(self) -> None:
        """
        Creates the config.ini file and saved the default settings in there.
        Reads the default settings into self.settings.
        :return: None
        """
        for section, options in self.DEFAULT_SETTINGS.items():
            self.settings[section] = {key: str(value) for key, value in options.items()}
        with open(self.settings_file_path, "w") as configfile:
            self.settings.write(configfile)
        self.settings.read(self.settings_file_path)

    def are_settings_valid(self) -> bool:
        """
        Validates the settings file values.
        :return: True of False (Valid or Invalid).
        """
        try:
            scanner_settings = self.settings["Scanner Settings"]
            interval = float(scanner_settings["interval"])
            if not (0 <= interval <= 60):
                return False
            timeout = float(scanner_settings["timeout"])
            if not (0 <= timeout <= 60):
                return False
            method = scanner_settings["method"].upper()
            if method not in {"ARP", "ICMP", "BOTH"}:
                return False
            if scanner_settings["retrieve hostname"].lower() not in {"true", "false"}:
                return False
            if scanner_settings["retrieve latency"].lower() not in {"true", "false"}:
                return False
            if scanner_settings["automatically add router"].lower() not in {"true", "false"}:
                return False

            fingerprint_settings = self.settings["Fingerprint Settings"]
            if fingerprint_settings["run well known port scan"].lower() not in {"true", "false"}:
                return False
            if fingerprint_settings["run full port scan"].lower() not in {"true", "false"}:
                return False
            if fingerprint_settings["run os detection scan"].lower() not in {"true", "false"}:
                return False
            if fingerprint_settings["scan udp ports"].lower() not in {"true", "false"}:
                return False
        except (KeyError, ValueError):
            return False

        return True


if __name__ == '__main__':
    print("Starting LAN Analyzer . . .")
    app = QApplication([])
    settings = Settings("config.ini")
    lan_analyzer = LanAnalyzer(settings.settings)
    sys.exit(app.exec_())
