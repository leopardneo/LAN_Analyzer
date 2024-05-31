"""
Author: Ofir Brovin
This file contains the host information view window.
"""
from PyQt5 import QtCore
from PyQt5.uic import loadUi
from PyQt5.QtGui import QFont, QCursor, QPixmap
from PyQt5.QtWidgets import QWidget, QLabel, QVBoxLayout, QSpacerItem, QSizePolicy, QPushButton


class HostInformationWindow(QWidget):
    """
    Host information management window class.
    """

    scans_str_trans: dict = {"well-known-ps": "Well-known port scan", "full-ps": "Full port scan",
                             "os-detect": "OS detection"}

    def __init__(self, host):
        """
        Initiates the host information window.
        :param host: Host object
        """

        super().__init__()

        self.host_obj = host
        if host:
            host_addr = host.ip_address
        else:
            host_addr = ""
        if not host_addr:
            self.setWindowTitle("No information available")
            self.title_label = QLabel("No information available")
            self.title_label.setFont(QFont("Segoe UI", 15))
            self.title_label.setAlignment(QtCore.Qt.AlignCenter)

            self.layout = QVBoxLayout()
            self.layout.addWidget(self.title_label)

            spacer_item = QSpacerItem(0, 15, QSizePolicy.Minimum, QSizePolicy.Minimum)
            self.layout.addSpacerItem(spacer_item)

            self.close_button = QPushButton("Close")
            self.close_button.clicked.connect(self.close)
            self.close_button.setFont(QFont("Segoe UI", 10))
            self.close_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
            self.layout.addWidget(self.close_button)

            self.setLayout(self.layout)
            return

        loadUi(r"src/view/windows/views/host_info_and_management_window.ui", self)
        self.setWindowTitle(f"{host_addr} Host Management")
        self.well_known_port_scan_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.full_port_scan_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.os_detection_scan_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        self.host_ports_advanced_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.host_clear_fp_scans_queue_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.host_cancel_fp_scan_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        self.close_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        self.title_label.setText(f"{host_addr} Management:")
        # self.image_label.setPixmap(QPixmap(f"LAN_Analyzer_Cache/view/icons/{host.type}.png").scaled(100, 100)) # Moved to update_host_information() - rem?

        self.ip_address_label.setText(f"IP Address: {host_addr}")
        self.mac_address_label.setText(f"MAC Address: {host.mac_address if host.mac_address else 'Not Available'}")
        self.mac_vendor_label.setText(f"MAC Vendor: {host.mac_vendor if host.mac_vendor else 'Not Available'}")
        self.hostname_label.setText(f"Hostname: {host.hostname if host.hostname else 'Not Available'}")
        self.ping_label.setText(
            f"Latency (ping): {str(host.response_time) + 'ms' if host.response_time != -1 else 'Not Available'}")

        self.update_host_information()

        self.close_button.clicked.connect(self.close)

    def _disable_fp_scan_button(self, scan_str: str) -> None:
        """
        Disables the button of the given fp scan.
        :param scan_str: The fp scan (str).
        :return: None
        """
        if scan_str == "Well-known port scan":
            self.well_known_port_scan_button.setDisabled(True)
        elif scan_str == "Full port scan":
            self.full_port_scan_button.setDisabled(True)
        elif scan_str == "OS detection":
            self.os_detection_scan_button.setDisabled(True)

    def update_fp_scans_section(self) -> None:
        """
        Updates the fingerprint scans section of the window.
        :return: None
        """
        self.well_known_port_scan_button.setEnabled(True)
        self.full_port_scan_button.setEnabled(True)
        self.os_detection_scan_button.setEnabled(True)

        if self.host_obj.fp_scan_in_progress:
            self.host_fp_scan_progress_bar.setEnabled(True)
            self.host_cancel_fp_scan_tb.setEnabled(True)
            self.scan_in_progress_label.setText(f"{self.host_obj.current_fp_scan_str} currently in progress.")
            self._disable_fp_scan_button(self.host_obj.current_fp_scan_str)
        else:
            self.scan_in_progress_label.setText("No scan currently in progress.")
            self.host_fp_scan_progress_bar.setDisabled(True)
            self.host_cancel_fp_scan_tb.setDisabled(True)
        # Scans queue section
        if self.host_obj.fp_scans_queue:
            scans_queue_str: str = "\n".join(
                tuple(map(lambda s: f"• {self.scans_str_trans[s]}", self.host_obj.fp_scans_queue)))
            self.scans_queue_value_label.setText(scans_queue_str)
            self.scans_queue_value_label.setEnabled(True)
            self.host_clear_fp_scans_queue_tb.setEnabled(True)
            for scan in self.host_obj.fp_scans_queue:
                self._disable_fp_scan_button(self.scans_str_trans[scan])
        else:
            self.scans_queue_value_label.setText("-Empty-")
            self.scans_queue_value_label.setDisabled(True)
            self.host_clear_fp_scans_queue_tb.setDisabled(True)

    def update_host_information(self) -> None:
        """
        Updates all the information labels.
        :return: None
        """
        host = self.host_obj

        # Re-set the device image in case the device type has changed
        if host.type in {"router", "printer"}:
            self.image_label.setPixmap(QPixmap(rf"src/view/icons/{host.type}.png").scaled(100, 100))
        else:
            self.image_label.setPixmap(QPixmap(rf"src/view/icons/{host.type}.png").scaled(130, 95))

        # PORTS update
        if host.scanned_ports is not None:
            self.scanned_ports_label.setText(
                f"Scanned Ports: {len(host.scanned_ports)} ({host.scanned_ports.start} - {host.scanned_ports.stop - 1})")
            self.host_ports_advanced_tb.setEnabled(True)
            total_open_amount: int = 0
            if not host.open_ports[0] and not host.open_ports[1]:
                self.open_ports_label.setText(f"Open Ports: 0")
            else:
                ports_str: str = ""
                if host.open_ports[0]:
                    total_open_amount += len(host.open_ports[0])
                    ports_str += f"TCP: {', '.join(str(p) for p in host.open_ports[0])}. "  # TODO: font
                if host.open_ports[1]:
                    total_open_amount += len(host.open_ports[1])
                    ports_str += f"UDP: {', '.join(str(p) for p in host.open_ports[1])}."

                self.open_ports_label.setText(f"Open Ports: {str(total_open_amount)} - {ports_str}")
            self.closed_ports_label.setText(f"Closed / Filtered Ports: {len(host.scanned_ports) - total_open_amount}")

        # OS update
        if host.operating_sys:
            self.os_label.setText(f"OS: {host.operating_sys}")

        # Fingerprinting scans section update
        self.update_fp_scans_section()

    def closeEvent(self, event):
        """
        This method is called when the window is about to be closed.
        Sets the host's object's information window attribute to None.
        :param event: Close event.
        :return:
        """
        self.host_obj.information_window = None

        event.accept()
