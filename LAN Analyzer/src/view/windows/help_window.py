"""
Author: Ofir Brovin.
This file contains the advanced help view window part of the LAN Analyzer application.
"""
from PyQt5 import QtCore
from PyQt5.QtGui import QIcon, QFont, QCursor
from PyQt5.QtWidgets import QWidget, QLabel, QPushButton, QVBoxLayout


class HelpWindow(QWidget):
    """
    Help view window class.
    """
    def __init__(self, message: str):
        """
        Initiates the help window.
        :param message: The help message (text).
        """
        super().__init__()
        self.setWindowTitle("Help")
        self.setWindowIcon(QIcon(r"src/view/icons/help_icon.png"))

        self.info_label = QLabel(message)
        self.info_label.setFont(QFont("Segoe UI", 16))

        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        self.close_button.setFont(QFont("Segoe UI", 10))
        self.close_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        self.layout = QVBoxLayout(self)
        self.layout.addWidget(self.info_label)
        self.layout.addWidget(self.close_button)
