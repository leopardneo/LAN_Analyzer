"""
Author: Ofir Brovin.
This file is the view module of the LAN Analyzer host connector client.
"""
import datetime

from PyQt5 import QtCore
from PyQt5.QtGui import QIcon, QColor, QCursor
from PyQt5.QtWidgets import QMainWindow, QListWidgetItem, QMessageBox
from PyQt5.uic import loadUi


class ConnectorClientWindow(QMainWindow):
    """
    (LAN Analyzer) connector client Window
    """
    def __init__(self):
        """
        Initiates the host connector window.
        """
        super().__init__()
        loadUi(r"src\view\window\connector_client_window.ui", self)

        self.send_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.reconnect_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        self.statusbar.showMessage("Connected to LAN Analyzer")

        self.show()

    def add_message(self, message: str, message_type: str, is_from_analyzer: bool) -> None:
        """
        Adds a message to the chat list widget.
        :param message: The message text
        :param message_type: The message type - ["REGULAR" | "WARNING" | "CRITICAL"]
        :param is_from_analyzer: Is the message from the analyzer - True or False
        :return: None
        """
        item = QListWidgetItem()
        if is_from_analyzer:
            message_author_str: str = "Analyzer Admin"
            item.setBackground(QColor("#E6F4EA"))
            item.setIcon(QIcon(r"src/view/icons/received_arrow.png"))
        else:
            message_author_str: str = "You"
            item.setBackground(QColor("#51c026"))
            item.setIcon(QIcon(r"src/view/icons/sent_arrow.png"))

        warning_message = False
        is_critical_warning = False
        if message_type == "WARNING":
            item.setBackground(QColor("#FFFF8F"))
            item.setIcon(QIcon(r"src/view/icons/warning.png"))
            warning_message = True
            is_critical_warning = False
        elif message_type == "CRITICAL":
            item.setBackground(QColor("#FF6347"))
            item.setIcon(QIcon(r"src/view/icons/critical_warning.png"))
            warning_message = True
            is_critical_warning = True
        elif message_type == "FINISHED_DOWNLOAD":
            item.setBackground(QColor("#92B3E8"))
            item.setIcon(QIcon(r"src/view/icons/file_downloaded.png"))

        current_date = datetime.datetime.now().strftime("%H:%M:%S")
        item.setText(f"{current_date} ({message_author_str})  :  {message}")

        self.chat_listWidget.addItem(item)
        # Apply the warning only after adding it to the chat list view so that it will be shown
        if warning_message:
            self._apply_warning(warning_text=message, is_critical=is_critical_warning)

    def _apply_warning(self, warning_text: str, is_critical) -> None:
        """
        Handles applying warning on the screen.
        Sets the last warning label and opens alert pop-up.
        :param warning_text: The warning text.
        :param is_critical: Is the warning critical type.
        :return: None
        """
        # Set the last warning label
        if is_critical:
            last_warning_label_text = f"[CRITICAL]\n{warning_text}"
        else:
            last_warning_label_text = warning_text
        self.last_warning_label.setText(last_warning_label_text)
        # Open warning pop-up alert
        alert_msgbox = QMessageBox()
        alert_msgbox.setText(warning_text)
        alert_msgbox.setStandardButtons(QMessageBox.Ok)
        if is_critical:
            alert_msgbox.setIcon(QMessageBox.Critical)
            alert_msgbox.setWindowTitle("Critical Warning")
        else:
            alert_msgbox.setIcon(QMessageBox.Warning)
            alert_msgbox.setWindowTitle("Warning")
        alert_msgbox.exec_()

    def analyzer_disconnected(self) -> None:
        """
        Sets the widgets to the lan disconnected state.
        :return: None
        """
        self.statusbar.setStyleSheet("color: red")
        self.statusbar.showMessage("LAN Analyzer Not Connected!")
        self.reconnect_button.setEnabled(True)
        self.chat_frame.setDisabled(True)

    def reconnecting_to_analyzer(self) -> None:
        """
        Sets the widgets to the reconnecting state.
        :return: None
        """
        self.reconnect_button.setDisabled(True)
        self.statusbar.setStyleSheet("")
        self.statusbar.showMessage("Attempting To Reconnect...")

    def analyzer_connected(self) -> None:
        """
        Sets the widgets to the lan connected state.
        :return: None
        """
        self.statusbar.setStyleSheet("")
        self.statusbar.showMessage("Connected to LAN Analyzer")
        self.reconnect_button.setDisabled(True)
        self.chat_frame.setEnabled(True)
