"""
Author: Ofir Brovin.
This file contains the send warning to a connected host view window part of the LAN Analyzer application.
"""
from PyQt5 import QtCore
from PyQt5.uic import loadUi
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QWidget


class SendWarningWindow(QWidget):
    """
    Send warning window class.
    """
    def __init__(self, warning_dest_host_obj: object = None, warning_dest_ip_addr: str = ""):
        """
        Initiates the send warning to a connected host window.
        :param warning_dest_host_obj: The connected host Host object.
        :param warning_dest_ip_addr: The connected host IP address.
        """
        self.host_obj = warning_dest_host_obj

        super().__init__()
        loadUi(r"src\view\windows\views\send_warning_window.ui", self)

        self.open_ports_warning_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.os_warning_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.send_warning_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        self.open_ports_warning_button.clicked.connect(self._handle_open_ports_warning_button)
        self.os_warning_button.clicked.connect(self._handle_os_warning_button)

        self.warning_plainTextEdit.textChanged.connect(self._handle_warning_text_changed)

        if self.host_obj:
            self.warning_title_label.setText(f"Send a warning to {self.host_obj.ip_address}")
        else:
            self.warning_title_label.setText(f"Send a warning to {warning_dest_ip_addr}")

        if self.host_obj and self.host_obj.open_ports:
            if self.host_obj.open_ports[0] or self.host_obj.open_ports[1]:
                self.open_ports_warning_button.setEnabled(True)

        if self.host_obj and self.host_obj.operating_sys:
            self.os_warning_button.setEnabled(True)

    def _handle_open_ports_warning_button(self) -> None:
        """
        Handles the warning about open ports button click.
        Creates the warning about the ports.
        :return: None
        """
        try:
            open_ports_warning_text: str = ""
            total_open_amount: int = 0
            if self.host_obj and self.host_obj.open_ports:
                if not self.host_obj.open_ports[0] and not self.host_obj.open_ports[1]:
                    open_ports_warning_text = "No open ports detected."
                else:
                    if self.host_obj.open_ports[0]:
                        total_open_amount += len(self.host_obj.open_ports[0])
                        open_ports_warning_text += f"TCP: {', '.join(str(p) for p in self.host_obj.open_ports[0])}. "
                    if self.host_obj.open_ports[1]:
                        total_open_amount += len(self.host_obj.open_ports[1])
                        open_ports_warning_text += f"UDP: {', '.join(str(p) for p in self.host_obj.open_ports[1])}."
                    open_ports_warning_text = f"You have {total_open_amount} open " \
                                              f"{'port' if total_open_amount == 1 else 'ports'}!\n" \
                                              f"Make sure the open ports are necessary ports only!\n" \
                                              f"Your open {'port' if total_open_amount == 1 else 'ports'}: {open_ports_warning_text}"

            self.warning_plainTextEdit.setPlainText(open_ports_warning_text)
        except Exception as e:
            print("ERROR ON OPEN PORTS WARNING BUTTON HANDLE:::", e)

    def _handle_os_warning_button(self) -> None:
        """
        Handles the warning about OS button click.
        Creates the warning about the OS.
        :return: None
        """
        os_warning_text: str
        host_os = self.host_obj.operating_sys if self.host_obj else ""
        if not host_os or "Not Available" in host_os:
            os_warning_text = "Running OS not detected."
        else:
            os_warning_text = f"{host_os} OS detected on your machine."

        self.warning_plainTextEdit.setPlainText(os_warning_text)

    def _handle_warning_text_changed(self):
        """
        Handles the warning text edit changed.
        Enables the send button if there is text in the text edit, disables it otherwise.
        :return: None
        """
        if self.warning_plainTextEdit.toPlainText():
            # If there is text in the warning
            self.send_warning_button.setEnabled(True)
        else:
            self.send_warning_button.setDisabled(True)

    def closeEvent(self, event):
        """
        This method is called when the window is about to be closed.
        Sets the host's object's information window attribute to None.
        :param event: Close event.
        :return:
        """
        if self.host_obj:
            self.host_obj.warning_window = None

        event.accept()
