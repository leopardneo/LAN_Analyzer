"""
Author: Ofir Brovin.
This file is a custom host representation widget created in PyQt5.
"""
from __future__ import annotations

from PyQt5.QtCore import QSize, Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPixmap, QPainter, QColor
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QHBoxLayout, QSpacerItem, QSizePolicy


class HostWidget(QWidget):
    """
    Custom Qt Widget to represent a host.
    """
    single_click_host_signal: pyqtSignal = pyqtSignal(object,
                                                      object)  # Transfers Host and HostWidget (self.host_obj, self)
    double_click_host_signal: pyqtSignal = pyqtSignal(object)  # Transfers Host (self.host_obj)
    host_flag_updated_signal: pyqtSignal = pyqtSignal(object)  # Transfers Host

    def __init__(self, host_obj):
        """
        Initiates the host widget.
        :param host_obj: The Host object (with the host's details).
        """
        super().__init__()
        self.host_obj = host_obj

        self.setFixedSize(160, 195)

        self.layout = QVBoxLayout()

        # Top marking icons
        self.icons_layout = QHBoxLayout()
        self.flag_label = QLabel()
        self.flag_label.setScaledContents(True)
        self.flag_label.setFixedSize(20, 22)
        self.icons_layout.addWidget(self.flag_label)

        spacer = QSpacerItem(0, 20, QSizePolicy.Expanding, QSizePolicy.Maximum)
        self.icons_layout.addSpacerItem(spacer)

        self.traffic_image_label = QLabel()  # Traffic image
        self.traffic_image_label.setScaledContents(True)
        self.traffic_image_label.setFixedSize(25, 26)
        self.icons_layout.addWidget(self.traffic_image_label)
        self.traffic_label = QLabel()  # Traffic text
        self.icons_layout.addWidget(self.traffic_label)
        self.high_traffic_marked: bool = False
        self.remove_traffic_mark_timer: QTimer | None = None

        spacer = QSpacerItem(0, 20, QSizePolicy.Expanding, QSizePolicy.Maximum)
        self.icons_layout.addSpacerItem(spacer)

        self.connected_label = QLabel()
        self.connected_label.setScaledContents(True)
        self.connected_label.setFixedSize(20, 22)
        self.icons_layout.addWidget(self.connected_label)

        margins = self.icons_layout.contentsMargins()
        # print("ICONS_MARGINS:", margins.left(), margins.top(), margins.right(), margins.bottom())
        self.icons_layout.setContentsMargins(margins.left() // 2, margins.top() // 2, margins.right() // 2,
                                             margins.bottom() // 2)

        self.layout.addLayout(self.icons_layout)

        # Image
        host_type = host_obj.type
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        if host_type == "computer":
            self.image_label.setPixmap(
                QPixmap("src/view/icons/computer.png").scaled(QSize(120, 120), Qt.KeepAspectRatio))
        elif host_type == "local_computer":
            self.image_label.setPixmap(QPixmap("src/view/icons/local_computer.png")
                                       .scaled(QSize(120, 120), Qt.KeepAspectRatio))
        elif host_type == "router":
            self.image_label.setPixmap(
                QPixmap("src/view/icons/router.png").scaled(QSize(110, 96), Qt.KeepAspectRatio))
        elif host_type == "printer":
            self.image_label.setPixmap(
                QPixmap("src/view/icons/printer.png").scaled(QSize(110, 96), Qt.KeepAspectRatio))
        elif host_type == "phone":
            pass  # TODO: ?

        self.layout.addWidget(self.image_label)

        # IP address label
        ip_address = host_obj.ip_address
        self.ip_addr_label = QLabel(ip_address if ip_address else "N/A")
        font_size = 17
        if len(ip_address) > 13:
            font_size = 13
        if len(ip_address) < 9:
            font_size = 18
        self.ip_addr_label.setFont(QFont("Segoe UI", font_size, QFont.Bold))
        self.ip_addr_label.setAlignment(Qt.AlignCenter)

        self.layout.addWidget(self.ip_addr_label)

        hostname = host_obj.hostname
        if hostname:
            # Hostname label, adjust font based on the hostname length
            new_hostname = hostname
            if len(hostname) > 15:
                new_hostname = hostname[0: 16] + "..."
            self.hostname_label = QLabel(new_hostname)
            font_size = 15
            if len(hostname) > 13:
                font_size = 10
            if len(hostname) < 10:
                font_size = 16
            self.hostname_label.setFont(QFont("Segoe UI", font_size))
            self.hostname_label.setAlignment(Qt.AlignCenter)

            self.layout.addWidget(self.hostname_label)

        self.setLayout(self.layout)
        margins = self.layout.contentsMargins()
        # print("MARGINS:", margins.left(), margins.top(), margins.right(), margins.bottom())
        self.layout.setContentsMargins(margins.left() // 2, margins.top() // 2, margins.right() // 2, margins.bottom())

        self.border_color = None
        if host_obj.flagged:
            self.set_flagged(flagged=True)
        if host_obj.script_connected:
            self.set_connected_icon(connected=True)

    def update_device_image(self) -> None:
        """
        Updates the image of the device based on its saved type.
        :return: None
        """
        host_type = self.host_obj.type
        if host_type == "computer":
            self.image_label.setPixmap(
                QPixmap("src/view/icons/computer.png").scaled(QSize(120, 120), Qt.KeepAspectRatio))
        elif host_type == "local_computer":
            self.image_label.setPixmap(QPixmap("src/view/icons/local_computer.png")
                                       .scaled(QSize(120, 120), Qt.KeepAspectRatio))
        elif host_type == "router":
            self.image_label.setPixmap(
                QPixmap("src/view/icons/router.png").scaled(QSize(110, 96), Qt.KeepAspectRatio))
        elif host_type == "printer":
            self.image_label.setPixmap(
                QPixmap("src/view/icons/printer.png").scaled(QSize(105, 105), Qt.KeepAspectRatio))
        elif host_type == "phone":
            pass  # TODO: ?
        self.update()

    def set_flagged(self, flagged: bool) -> None:
        """
        Sets the flag icon of the host widget.
        :param flagged: The flag (True of False)
        :return: None
        """
        if flagged:
            self.flag_label.setPixmap(QPixmap(r"src/view/icons/flag.png"))
            self.host_obj.flagged = True
        else:
            self.flag_label.clear()
            self.host_obj.flagged = False
        self.update()
        self.host_flag_updated_signal.emit(self.host_obj)

    def set_traffic_icon(self, is_high_traffic: bool):
        """
        Sets the traffic icon of the host widget.
        :param is_high_traffic: Is the traffic high traffic (True of False).
        :return: None
        """
        if self.high_traffic_marked:
            return
        if is_high_traffic:
            self.high_traffic_marked = True
            self.traffic_image_label.setPixmap(QPixmap(r"src/view/icons/high_traffic.png"))
            self.traffic_label.setText("<b>High Traffic</b>")
        else:
            self.traffic_image_label.setPixmap(QPixmap(r"src/view/icons/traffic.png"))
            self.traffic_label.setText("<b>Traffic</b>")

        self.remove_traffic_mark_timer = QTimer()
        self.remove_traffic_mark_timer.timeout.connect(self._timeout_rem_traffic_mark)
        self.remove_traffic_mark_timer.start(10000)  # 10 seconds delay

    def _timeout_rem_traffic_mark(self) -> None:
        """
        Removes the traffic mark of the host widget after the timeout.
        :return: None
        """
        self.traffic_image_label.clear()
        self.traffic_label.clear()
        self.high_traffic_marked = False

        # Stop the timer
        self.remove_traffic_mark_timer.stop()
        self.remove_traffic_mark_timer = None

    def set_connected_icon(self, connected: bool) -> None:
        """
        Sets the connected icon of the host widget.
        :param connected: Is connected (True of False)
        :return: None
        """
        if connected:
            self.connected_label.setPixmap(QPixmap(r"src/view/icons/connected.png"))
        else:
            self.connected_label.clear()
        self.update()

    def paintEvent(self, event) -> None:
        """
        Paints the border of the widget in the border color (blue)
        :param event: The paint event (QWidget).
        :return: None
        """
        if self.border_color:
            painter = QPainter(self)
            painter.setPen(QColor(self.border_color))
            painter.drawRect(self.rect())

    def mousePressEvent(self, event) -> None:
        """
        Handles the mouse press event.
        :param event: The mouse press event (QWidget).
        :return: None
        """
        if event.button() == Qt.LeftButton:
            self.single_click_host_signal.emit(self.host_obj, self)

            # Mark the border
            self.border_color = "blue"
            self.update()

    def mouseDoubleClickEvent(self, event) -> None:
        """
        Handles the mouse double click event.
        :param event: The mouse double click event (QWidget).
        :return: None
        """
        if event.button() == Qt.LeftButton:
            self.double_click_host_signal.emit(self.host_obj)

            # Remove the border mark
            self.border_color = None
            self.update()
