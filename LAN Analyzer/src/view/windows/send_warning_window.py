from PyQt5 import QtCore
from PyQt5.QtCore import pyqtSignal
from PyQt5.uic import loadUi
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QWidget


class SendWarningWindow(QWidget):
    def __init__(self, host_obj: object):
        self.host_obj = host_obj

        super().__init__()
        loadUi(r"src\view\windows\views\send_warning_window.ui", self)

        self.open_ports_warning_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.os_warning_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.send_warning_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        self.open_ports_warning_button.clicked.connect(self.handle_open_ports_warning_button)
        self.os_warning_button.clicked.connect(self.handle_os_warning_button)

        self.warning_plainTextEdit.textChanged.connect(self.handle_warning_text_changed)

        self.warning_title_label.setText(f"Send a warning to {host_obj.ip_address}")

        if host_obj.open_ports:
            if host_obj.open_ports[0] or host_obj.open_ports[1]:
                self.open_ports_warning_button.setEnabled(True)

        if host_obj.operating_sys:
            print(host_obj.operating_sys)
            self.os_warning_button.setEnabled(True)

    def handle_open_ports_warning_button(self):
        try:
            open_ports_warning_text: str = ""
            total_open_amount: int = 0
            if self.host_obj.open_ports:
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

    def handle_os_warning_button(self):
        os_warning_text: str = ""
        host_os = self.host_obj.operating_sys
        if not host_os or "Not Available" in host_os:
            os_warning_text = "Running OS not detected."
        else:
            os_warning_text = f"{host_os} OS detected on your machine."

        self.warning_plainTextEdit.setPlainText(os_warning_text)

    def handle_warning_text_changed(self):
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
        self.host_obj.warning_window = None

        event.accept()
