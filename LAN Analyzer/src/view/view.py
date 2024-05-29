"""
Author: Ofir Brovin
This file is the view module of the LAN Analyzer application.
"""
from __future__ import annotations

import sys
if __name__ == '__main__':
    sys.exit("This file is part of the LAN Analyzer application and cannot be run independently")

import re
import time
import ipaddress

from datetime import datetime
from typing import List, Tuple, Dict

from PyQt5 import QtCore
from PyQt5.QtCore import QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QIcon, QCursor, QFont, QPainter, QPixmap, QColor
from PyQt5.QtWidgets import QMainWindow, QTableWidgetItem, QAbstractItemView, QHeaderView, QTableWidget, QWidget, \
    QLabel, QVBoxLayout, QSpacerItem, QSizePolicy, QPushButton, QGraphicsView, QMessageBox, QListWidgetItem
from PyQt5.uic import loadUi

from .custom_widgets import NetworkTopology, Switch
from .logger import Logger
from .windows import HelpWindow, HostInformationWindow


class AnalyzerWindow(QMainWindow):
    """
    LAN Analyzer Window
    """
    scan_interval_finished_signal: pyqtSignal = pyqtSignal()  # Signal emits when the scan interval time reaches 0.

    host_info_window_created_signal: pyqtSignal = pyqtSignal(object)  # Emits when a host's info win is opened -
    # carries the host obj
    port_scan_button_signal: pyqtSignal = pyqtSignal(str, object)  # Carries scan type (well-known or full) and Host obj
    os_detection_scan_button_signal: pyqtSignal = pyqtSignal(object)  # Carries Host obj

    host_clear_fp_scans_queue_signal: pyqtSignal = pyqtSignal(
        object)  # Emits when bin button pressed - carries host obj
    host_stop_fp_scan_signal: pyqtSignal = pyqtSignal(object)  # Emits when stop (X) button pressed - carries host obj
    host_open_advanced_port_win_signal: pyqtSignal = pyqtSignal(object)  # Emits when the open advanced ports window

    # clicked from the host info window

    def __init__(self):
        """
        Initiates the analyzer main window
        """
        super().__init__()
        loadUi(r"src\view\windows\views\lan_analyzer_window.ui", self)
        self.showMaximized()

        self.start_scan_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        header = self.hosts_table_widget.horizontalHeader()
        # header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        # header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.hosts_table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.hosts_table_widget.setSelectionBehavior(QTableWidget.SelectRows)
        self.online_hosts_table_address_to_row: Dict[str, int] = {}

        self.start_ip_line.textChanged.connect(
            lambda new_text: self.handle_ip_lineedit_change(new_text, "start"))
        self.end_ip_line.textChanged.connect(
            lambda new_text: self.handle_ip_lineedit_change(new_text, "end"))

        # Sidebar settings
        self.side_bar_icons.setHidden(True)
        self.stackedWidget.setCurrentIndex(0)
        self.scanner_button_1.setChecked(True)
        self.sidebar_button_1.setChecked(True)

        # Sidebar buttons connect
        self.scanner_button_1.clicked.connect(self.load_scanner_screen)
        self.scanner_button_2.clicked.connect(self.load_scanner_screen)
        self.connected_hosts_button_1.clicked.connect(self.load_connected_hosts_screen)
        self.connected_hosts_button_2.clicked.connect(self.load_connected_hosts_screen)
        self.traffic_sniffer_button_1.clicked.connect(self.load_traffic_sniffer_screen)
        self.traffic_sniffer_button_2.clicked.connect(self.load_traffic_sniffer_screen)
        self.logger_button_1.clicked.connect(self.load_logger_screen)
        self.logger_button_2.clicked.connect(self.load_logger_screen)
        self.settings_button_1.clicked.connect(self.load_settings_screen)
        self.settings_button_2.clicked.connect(self.load_settings_screen)

        # Scan interval
        self.interval_time: int = 0
        self.scan_interval_timer: QTimer | None = None
        self.scan_interval_remain_lcdNumber.display("05:00")

        self.scan_interval_cb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.scan_interval_cb.stateChanged.connect(self.stop_scan_interval_timer_and_reset_time)

        self.scan_interval_time_spinBox.valueChanged.connect(self.handle_scan_interval_spinbox_changed)

        self.start_scan_interval_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.start_scan_interval_tb.clicked.connect(self.handle_scan_interval_start)

        # Topology search
        self.search_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.search_tb.clicked.connect(self.handle_search_in_topology)
        self.cancel_search_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.cancel_search_tb.clicked.connect(self.handle_cancel_search_button)
        self.device_type_search_comboBox.activated.connect(self.handle_search_in_topology)
        self.show_flagged_only_cb.stateChanged.connect(self.handle_search_in_topology)

        # Hosts connector buttons
        self.disconnect_host_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.flag_host_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.info_win_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.send_file_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.send_warning_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.clear_host_chat_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        # Sniffer setting help button
        self.update_traffic_graphs_auto_help_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        # Settings help buttons
        self.scan_speed_acur_help_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.scan_method_setting_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.scanned_host_info_setting_help_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.router_setting_help_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.fingerprint_setting_help_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.udp_ports_setting_tb.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        self.save_settings_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))

        self.update_traffic_graphs_auto_help_tb.clicked.connect(lambda: self.show_help_window(-1))
        self.scan_speed_acur_help_tb.clicked.connect(lambda: self.show_help_window(0))
        self.scan_method_setting_tb.clicked.connect(lambda: self.show_help_window(1))
        self.scanned_host_info_setting_help_tb.clicked.connect(lambda: self.show_help_window(2))
        self.router_setting_help_tb.clicked.connect(lambda: self.show_help_window(3))
        self.fingerprint_setting_help_tb.clicked.connect(lambda: self.show_help_window(4))
        self.udp_ports_setting_tb.clicked.connect(lambda: self.show_help_window(5))

        # Fp port scans settings switches - not allowing both to be on.
        self.well_known_port_scan_fp_setting_switch.clicked.connect(self.handle_well_known_port_scan_setting_cb_change)
        self.full_port_scan_fp_setting_switch.clicked.connect(self.handle_full_port_scan_setting_cb_change)

        self.finished_timer = None
        self.scan_finished_window = None
        self.setting_help_win: HelpWindow | None = None

        # NETWORK TOPOLOGY VIEW SET-UP
        # Add the topology graph scene.
        self.network_topology_viewer = NetworkTopology(self)  # The topology SCENE
        self.topology_view.setScene(self.network_topology_viewer)
        # Enable zooming
        self.topology_view.setInteractive(True)
        self.topology_view.setRenderHint(QPainter.Antialiasing, True)
        self.topology_view.setRenderHint(QPainter.SmoothPixmapTransform, True)
        self.topology_view.setRenderHint(QPainter.HighQualityAntialiasing, True)
        self.topology_view.setRenderHint(QPainter.TextAntialiasing, True)
        self.topology_view.setRenderHint(QPainter.NonCosmeticDefaultPen, True)

        self.topology_view.wheelEvent = self.topology_view_wheel_event
        # Enable dragging
        self.topology_view.setDragMode(QGraphicsView.ScrollHandDrag)

        self.hosts_widgets_list: list = []

        # EVENTS LOGGER
        self.logger: Logger = Logger(self.logger_listWidget)
        self.logger_listWidget.itemClicked.connect(self.handle_logger_event_clicked)

    def handle_scan_interval_spinbox_changed(self):
        if self.scan_interval_timer and self.scan_interval_timer.isActive():
            return
        else:
            print("THERE IS NO TIMER ACTIVE, changing label")
        minutes = self.scan_interval_time_spinBox.value()
        self.set_interval_time_in_lcdnumber(minutes, 0)

    def handle_scan_interval_start(self):
        minutes = self.scan_interval_time_spinBox.value()
        self.set_interval_time_in_lcdnumber(minutes, 0)
        self.interval_time = minutes * 60
        self.scan_interval_timer = QTimer()
        self.scan_interval_timer.timeout.connect(self.handle_scan_interval_change_countdown)
        self.scan_interval_timer.start(1 * 1000)

    def handle_scan_interval_change_countdown(self):
        self.interval_time -= 1
        minutes = self.interval_time // 60
        seconds = self.interval_time % 60
        self.set_interval_time_in_lcdnumber(minutes, seconds)
        if self.interval_time == 0:
            print("STOPPING TIMER OF SCAN INTERVAL! - INTERVAL FINISHED!!!")
            self.stop_scan_interval_timer_and_reset_time()
            self.scan_interval_finished_signal.emit()

    def set_interval_time_in_lcdnumber(self, minutes: int, seconds: int):
        self.scan_interval_remain_lcdNumber.display(f"{str(minutes).zfill(2)}:{str(seconds).zfill(2)}")

    def stop_scan_interval_timer_and_reset_time(self):
        if self.scan_interval_timer and self.scan_interval_timer.isActive():
            self.scan_interval_timer.stop()
            minutes = self.scan_interval_time_spinBox.value()
            self.scan_interval_remain_lcdNumber.display(f"{str(minutes).zfill(2)}:00")

    def handle_well_known_port_scan_setting_cb_change(self):
        if self.well_known_port_scan_fp_setting_switch.isChecked():
            full_port_switch = self.full_port_scan_fp_setting_switch
            if full_port_switch.isChecked():
                full_port_switch.setChecked(False)
                full_port_switch.animate()

    def handle_full_port_scan_setting_cb_change(self):
        if self.full_port_scan_fp_setting_switch.isChecked():
            well_known_switch = self.well_known_port_scan_fp_setting_switch
            if well_known_switch.isChecked():
                well_known_switch.setChecked(False)
                well_known_switch.animate()

    def load_scanner_screen(self):
        self.stackedWidget.setCurrentIndex(0)

    def load_connected_hosts_screen(self):
        self.connected_hosts_listWidget.clearSelection()
        self.chat_with_label.setText(f"Chat With:")
        self.flag_host_button.setText("Flag Host")
        self.chat_listWidget.clear()
        self.chat_frame.setDisabled(True)
        self.tools_frame.setDisabled(True)

        self.disconnect_host_button.setDisabled(True)
        self.flag_host_button.setDisabled(True)
        self.info_win_button.setDisabled(True)

        self.stackedWidget.setCurrentIndex(1)

    def add_host_to_connected_list_widget(self, addr: Tuple[str, int], hostname: str):
        item = QListWidgetItem()
        if hostname:
            hostname_str = f" - {hostname}"
        else:
            hostname_str = ""
        item.setText(f"{addr[0]} : {addr[1]}{hostname_str}")

        # Item computer icon
        icon = QIcon(r"src/view/icons/computer.png")
        item.setIcon(icon)

        # Background color
        item.setBackground(QColor("#E6F4EA"))

        self.connected_hosts_listWidget.addItem(item)

    def remove_host_from_connected_list_widget(self, host_addr: Tuple[str, int]):
        item_text = f"{host_addr[0]} : {host_addr[1]}"
        list_widget = self.connected_hosts_listWidget
        for i in range(list_widget.count()):
            item = list_widget.item(i)
            if item_text in item.text():
                list_widget.takeItem(i)
                break

    def load_host_chat(self, host_addr: Tuple[str, int], chat_history: List[Tuple[str, int, str]]):
        self.chat_with_label.setText(f"Chat With: {host_addr[0]}")

        self.chat_listWidget.clear()
        if not chat_history:
            self.chat_listWidget.addItem("No Messages.")
        for message in chat_history:
            self.add_message_to_chat(host_addr, message)

        self.chat_frame.setEnabled(True)
        self.tools_frame.setEnabled(True)

        self.disconnect_host_button.setEnabled(True)
        self.info_win_button.setEnabled(True)

        host_topology_widget = self.find_host_widget_from_topology(host_ip_address=host_addr[0])
        if host_topology_widget:
            self.flag_host_button.setEnabled(True)
            if host_topology_widget.host_obj.flagged:
                self.flag_host_button.setText("Remove Flag")
            else:
                self.flag_host_button.setText("Flag Host")

    def add_message_to_chat(self, host_addr: Tuple[str, int], message: Tuple[str, int, str, str]):
        """
        Adds a message to the chat list widget
        :param host_addr: The message host address
        :param message: The message tuple containing [timestamp, is_from_host, text, type (reg / warn ...)]
        :return:
        """
        item = QListWidgetItem()
        if message[1] == 1:
            # It's a regular message from the client
            message_author_str: str = f"{host_addr[0]}"
            item.setBackground(QColor("#E6F4EA"))
            item.setIcon(QIcon(r"src/view/icons/received_arrow.png"))
        else:
            # Message (sent) from the analyzer admin
            message_author_str: str = f"Analyzer Admin"
            item.setBackground(QColor("#51c026"))
            item.setIcon(QIcon(r"src/view/icons/sent_arrow.png"))

        if message[3] == "WARNING":
            item.setBackground(QColor("#FFFF8F"))
            item.setIcon(QIcon(r"src/view/icons/warning.png"))
        elif message[3] == "CRITICAL":
            item.setBackground(QColor("#FF6347"))
            item.setIcon(QIcon(r"src/view/icons/critical_warning.png"))
        elif message[3] == "FILE_SENT":
            item.setBackground(QColor("#92B3E8"))
            item.setIcon(QIcon(r"src/view/icons/sent_file.png"))

        timestamp_split = message[0].split(" ")  # [date, time (hour:minutes:seconds)]
        # TODO - save information such as datetime to show when message is double clicked / DONE IN DB (I think)
        full_hour_time = timestamp_split[1].split(":")
        full_hour_time[0] = str(int(full_hour_time[0]) + 3).zfill(1)  # Adding 3 hours to correct the timezone
        full_hour_time = ":".join(full_hour_time)
        item.setText(f"{full_hour_time} ({message_author_str})  :  {message[2]}")

        self.chat_listWidget.addItem(item)

    def mark_hosts_connector_as_open(self, listening_addr: Tuple[str, int]):
        self.status_image_label.setPixmap(QPixmap(r"src/view/icons/green_dot.png")
                                          .scaled(25, 25, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.status_label.setText("Hosts connector is activated. Listening for new connections.")

        self.allow_new_hosts_connections_checkbox.setEnabled(True)
        self.connected_hosts_listWidget.setEnabled(True)

        self.listening_address_label.setText(f"Listening Address: {listening_addr[0]}:{listening_addr[1]}")

    def mark_hosts_connector_as_not_accepting(self):
        self.status_image_label.setPixmap(QPixmap(r"src/view/icons/orange_dot.png")
                                          .scaled(22, 22, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.status_label.setText("Hosts connector is activated. Not accepting new connections.")

    # ------ TRAFFIC SNIFFER FUNCTIONS ------
    def load_traffic_sniffer_screen(self):
        self.sniffer_hosts_list_widget.clearSelection()
        self.sniffer_hosts_list_widget.setCurrentItem(None)
        self.inbound_traffic_graph.clear_plot()
        self.outbound_traffic_graph.clear_plot()
        self.traffic_rate_graphs_title_label.setDisabled(True)
        self.traffic_rate_graphs_title_label.setText("Traffic Rate Graphs:")
        self.update_traffic_graphs_auto_cb.setDisabled(True)
        self.traffic_graphs_frame.setDisabled(True)
        self.stackedWidget.setCurrentIndex(2)

    def add_host_to_traffic_hosts_list_widget(self, host_mac_address: str, host_ip_address: str, host_type: str):
        item = QListWidgetItem()
        if host_ip_address:
            ip_address_str = f" - {host_ip_address}"
        else:
            ip_address_str = ""
        item.setText(f"{host_mac_address}{ip_address_str}")

        # Setting matching icon
        icon = QIcon(rf"src/view/icons/{host_type}.png")
        item.setIcon(icon)

        # Background color
        item.setBackground(QColor("#FFE5A1"))  # Same color as traffic event in logger

        self.sniffer_hosts_list_widget.addItem(item)

    def load_host_traffic_graphs(self, times: List[datetime], incoming_data: List[int], outgoing_data: List[int]) -> None:
        """
        Loads a given hosts graphs to the GUI. (plots the graphs using matplotlib (TrafficRateGraph custom widget))
        :param times: The data times (X-axis)
        :param incoming_data: Incoming packets rate (Y axis for the incoming traffic graph)
        :param outgoing_data: Outgoing packets rate (Y axis for the outgoing traffic graph)
        :return: None
        """
        start_plot_time = time.time()
        self.inbound_traffic_graph.update_data(incoming_data, times, "orange")
        self.outbound_traffic_graph.update_data(outgoing_data, times, "blue")
        print("PLOTTING TOOK:::", time.time() - start_plot_time)

    def mark_sniffer_as_open(self):
        self.sniffer_status_image_label.setPixmap(QPixmap(r"src/view/icons/eye-scanner.png")
                                                  .scaled(40, 40, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        self.sniffer_status_label.setText("Sniffer is active.")

        self.sniffer_hosts_list_widget.setEnabled(True)

    def load_logger_screen(self):
        self.stackedWidget.setCurrentIndex(3)
        self.logger_listWidget.clearSelection()
        self.logger_event_details_label.setText("Select an event to show info.")

    def handle_logger_event_clicked(self, event_item: QListWidgetItem) -> None:
        """
        Shows event information in the label when a log event is selected.
        :param event_item: The logger event that was selected.
        :return: None
        """
        if not event_item:
            return
        event_index = self.logger_listWidget.row(event_item)
        event_obj = self.logger.get_event_at_index(event_index)
        if event_obj:
            event_message = event_obj.event_message.replace('\n', '<br>')  # Matching to HTML formatting
            self.logger_event_details_label.setText(f"<b>Event:</b> {event_message}<br>"
                                                    f"<b>Event type:</b> {event_obj.event_type.capitalize()}<br>"
                                                    f"<b>Event timestamp:</b> {event_obj.event_timestamp}")

    def load_settings_screen(self):
        self.stackedWidget.setCurrentIndex(4)

    def topology_view_wheel_event(self, event):
        """
        Handles the scroll-wheel event on the topology view widget.
        """
        try:
            # Zoom in/out based on the direction of the mouse wheel
            SCALE_FACTOR = 1.2
            if event.angleDelta().y() > 0:
                self.topology_view.scale(SCALE_FACTOR, SCALE_FACTOR)
            else:
                self.topology_view.scale(1 / SCALE_FACTOR, 1 / SCALE_FACTOR)
        except Exception as be:
            print("TOPOLOGY WHEEL EVENT BE:", be)

    def handle_interfaces_combobox_change(self, start_addr: str, end_addr: str):
        """
        Handles selection of interface in the combobox.
        Enables the Start Scan button and sets the start and end ip in the labels.
        :param start_addr: Start scan ip address to set in start ip label
        :param end_addr: End scan ip address to set in end ip label
        :return:
        """
        self.start_scan_button.setEnabled(True)
        self.start_ip_line.setText(start_addr)
        self.end_ip_line.setText(end_addr)

    def handle_ip_lineedit_change(self, new_text: str, start_or_end_entry: str):
        """
        Handles input change on the ip address labels.
        :param new_text: The new input
        :param start_or_end_entry: Indicates in which label the input occurred.
        :return:
        """
        # Regular expression for IPv4 addresses
        ip_pattern = re.compile(
            r"^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\."
            r"(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$"
        )

        if ip_pattern.match(new_text):
            # __ Valid IP address __
            try:
                start_ip_int: int = 0
                end_ip_int: int = 0
                if start_or_end_entry == "start" and self.end_ip_line.text() and ip_pattern.match(
                        self.end_ip_line.text()):
                    start_ip_int = int(ipaddress.IPv4Address(new_text))
                    end_ip_int = int(ipaddress.IPv4Address(self.end_ip_line.text()))
                elif start_or_end_entry == "end" and self.start_ip_line.text() and ip_pattern.match(
                        self.start_ip_line.text()):
                    start_ip_int = int(ipaddress.IPv4Address(self.start_ip_line.text()))
                    end_ip_int = int(ipaddress.IPv4Address(new_text))
                else:
                    valid_var = "valid"

                if start_ip_int > end_ip_int:
                    valid_var = "invalid"
                elif start_ip_int < end_ip_int:
                    self.change_ip_lineedit_color("valid", "both")
                    return
                elif start_ip_int == end_ip_int != 0:
                    self.change_ip_lineedit_color("valid", "both")
                    return
            except Exception as rt:
                print("RT:", rt)
            # UPDATE NETWORK:
            pass  # TODO - Remove
            # UPDATE GUI:
        else:
            # __ Invalid IP address __
            valid_var = "invalid"

        try:
            self.change_ip_lineedit_color(valid_var, start_or_end_entry)
        except Exception as erf:
            print("ERF:", erf)

    def change_ip_lineedit_color(self, valid_status: str, start_or_end_entry: str):
        """
        Colors the label based on whether the input is valid or not.
        :param valid_status: The input validation status (given by the handle_ip_lineedit_change function)
        :param start_or_end_entry: Indicates in which label the input occurred.
        :return:
        """
        if valid_status == "valid":
            # Valid IP address - enable scan button and clear border color
            if start_or_end_entry == "both":
                if self.interfaces_combobox.currentIndex() not in {0, 1}:
                    self.start_scan_button.setEnabled(True)
                self.start_ip_line.setStyleSheet("border: 1px solid black; font: 10pt 'Segoe UI';")
                self.end_ip_line.setStyleSheet("border: 1px solid black; font: 10pt 'Segoe UI';")
            elif start_or_end_entry == "start":
                self.start_ip_line.setStyleSheet("border: 1px solid black; font: 10pt 'Segoe UI';")
            else:
                self.end_ip_line.setStyleSheet("border: 1px solid black; font: 10pt 'Segoe UI';")
        else:
            # Invalid IP address - disable scan button
            self.start_scan_button.setDisabled(True)
            # Set the line edit's border color to red
            if start_or_end_entry == "start":
                self.start_ip_line.setStyleSheet("border: 1px solid red; font: 10pt 'Segoe UI';")
            else:
                self.end_ip_line.setStyleSheet("border: 1px solid red; font: 10pt 'Segoe UI';")

    def scan_start(self):
        """
        Updates the GUI on scan start.
        :return:
        """
        try:
            self.start_scan_button.setText("Stop Scan")
            new_icon = QIcon(r"src/view/icons/stop_scan_icon.png")
            self.start_scan_button.setIcon(new_icon)

            self.start_ip_line.setDisabled(True)
            self.end_ip_line.setDisabled(True)
            self.interfaces_combobox.setDisabled(True)

            self.scan_interval_cb.setDisabled(True)
            self.scan_interval_time_spinBox.setDisabled(True)
            self.interval_minutes_label.setDisabled(True)
            self.start_scan_interval_tb.setDisabled(True)
            self.scan_interval_remain_lcdNumber.setDisabled(True)
            self.stop_scan_interval_timer_and_reset_time()  # Stop the interval timer if its active

            # Clear online hosts table and topology view
            # TODO - 10/05/24
            # self.hosts_table_widget.setRowCount(0)
            #
            # self.network_topology_viewer.clear()
            # self.network_topology_viewer = NetworkTopology(self)
            # self.topology_view.setScene(self.network_topology_viewer)
            #
            # self.host_info_label.setText("Click on a host to view info.")
            # self.hosts_widgets_list = []
        except Exception as e:
            print("ERROR START SCAN", e)

    def scan_finished(self, hosts_list: list, router_host, scan_time: float,
                      scanned_addrs_amount: int):
        """
        Function called from controller on scan end.
        Creates the scan finished pop-up window and creates the topology view.
        :param hosts_list: The scanned hosts list (Host objects).
        :param router_host: Router Host object.
        :param scan_time: The scan duration (in seconds)
        :param scanned_addrs_amount: Amount of address scanned (if the scan wasn't stopped it's all the addrs)
        :return:
        """
        self.start_scan_button.setText("Start Scan")
        new_icon = QIcon(r"src/view/icons/start_scan_icon.png")
        self.start_scan_button.setIcon(new_icon)

        self.start_scan_button.setEnabled(True)
        self.start_ip_line.setEnabled(True)
        self.end_ip_line.setEnabled(True)
        self.interfaces_combobox.setEnabled(True)

        # Scan interval
        self.scan_interval_cb.setEnabled(True)
        if self.scan_interval_cb.isChecked():
            self.scan_interval_time_spinBox.setEnabled(True)
            self.interval_minutes_label.setEnabled(True)
            self.start_scan_interval_tb.setEnabled(True)
            self.scan_interval_remain_lcdNumber.setEnabled(True)
            self.handle_scan_interval_start()

        # Topology search
        self.topology_search_frame.setEnabled(True)

        self.finished_timer = QTimer()
        # /*
        # Switched because: a. no need for thread,
        # b. got an error printed (but still worked) that timer cant be killed from another thread
        # self.finished_timer.timeout.connect(
        #     lambda: threading.Thread(
        #         target=self.clear_prog_bar_after_scan).start())
        # */
        self.finished_timer.timeout.connect(self.clear_prog_bar_after_scan)
        self.finished_timer.start(2 * 1000)  # 2 seconds delay

        responding_hosts_count = len(hosts_list) + (1 if router_host.ip_address else 0)
        self.scan_finished_window = ScanFinishedWindow(scan_time, scanned_addrs_amount, responding_hosts_count)
        self.scan_finished_window.show()

        # ****
        try:
            self.load_topology_view(self.network_topology_viewer.create_hosts_widgets_list(hosts_list), router_host,
                                    True,
                                    should_copy=False)  # No need to copy the widgets as they are new created by create_hosts_widgets_list()
        except Exception as toperr:
            print("ERROR TOPERR:", toperr)
        # ****

    def load_topology_view(self, hosts_widgets: list, router_obj: object, is_full_topology: bool, should_copy=True):
        """

        :param hosts_widgets:
        :param router_obj:
        :param is_full_topology:
        :param should_copy:
        :return:
        """
        network_topology_viewer_obj = self.network_topology_viewer

        if should_copy:
            # Need to create new HostWidgets because when clearing the scene the widgets get destroyed
            new_hosts_widgets = network_topology_viewer_obj.create_copy_hosts_widgets_list(hosts_widgets)
        else:
            new_hosts_widgets = hosts_widgets

        network_topology_viewer_obj.create_topology(new_hosts_widgets, router_obj, is_full_topology)
        self.hosts_widgets_list = network_topology_viewer_obj.hosts_widgets
        # Updating shown hosts counter label
        self.topology_shown_hosts_count_label.setText(
            f"{len(self.hosts_widgets_list)}/{len(network_topology_viewer_obj.full_topology_widgets)} Shown")

        # Connecting the mouse click signals of each host widget
        for host_widg in self.hosts_widgets_list:
            host_widg.single_click_host_signal.connect(
                lambda host_obj, host_widg: self.host_click_connect(host_obj, host_widg))
            host_widg.double_click_host_signal.connect(lambda host: self.show_host_information(host))
            host_widg.host_flag_updated_signal.connect(lambda host: self.handle_search_in_topology())  # TODO - no need to carry the host obj in the signal - rem?

    def handle_search_in_topology(self):
        try:
            search_field_type: str = self.search_value_type_comboBox.currentText()
            search_device_type: str = self.device_type_search_comboBox.currentText().lower()
            search_string: str = self.search_bar_lineEdit.text().lower()

            self.search_bar_lineEdit.setStyleSheet("")

            print("search_field_type:::", search_field_type)
            print("search_device_type:::", search_device_type)
            print("search_string:::", search_string)

            network_topology_viewer_obj = self.network_topology_viewer

            is_full_topology = (False if (self.search_bar_lineEdit.text() or
                                          self.device_type_search_comboBox.currentIndex() != 0 or
                                          self.show_flagged_only_cb.isChecked()) else True)
            if is_full_topology:
                if network_topology_viewer_obj.is_full_topology_shown:
                    print("FULL TOPOLOGY REQUESTED WHILE FULL ONE IS ALREADY DISPLAYED - RETURNING")
                    return
                else:
                    full_topology_widgets = network_topology_viewer_obj.full_topology_widgets
                    if len(full_topology_widgets) == 1:
                        return self.load_topology_view([], full_topology_widgets[0].host_obj, True)
                    else:
                        return self.load_topology_view(full_topology_widgets[1:], full_topology_widgets[0].host_obj,
                                                       True)

            valid_hosts_widgets: list = []
            router_obj = None
            for host_widget in network_topology_viewer_obj.full_topology_widgets:
                host_obj = host_widget.host_obj
                if search_field_type == "IP Address":
                    if not query_string(query=search_string, string=host_obj.ip_address):
                        print(search_string, "NOT IN:", host_obj.ip_address)
                        continue
                elif search_field_type == "Hostname":
                    if not query_string(query=search_string, string=host_obj.hostname.lower()):
                        continue
                elif search_field_type == "MAC Address":
                    if not query_string(query=search_string, string=host_obj.mac_address.lower()):
                        continue
                elif search_field_type == "MAC Vendor":
                    if not query_string(query=search_string, string=host_obj.mac_vendor.lower()):
                        continue
                elif search_field_type == "Open Ports":
                    # TODO - open ports syntax implement
                    if not self.open_ports_query(query=search_string, ports=host_obj.open_ports):
                        continue  # TODO
                    # if not host_obj.open_ports or \
                    #         ((search_string not in host_obj.open_ports[0]) and (
                    #                 search_string not in host_obj.open_ports[1])):
                    #     # Not in open TCP ports and not in open UDP ports ^
                    #     continue
                elif search_field_type == "Operating System":
                    if not query_string(query=search_string, string=host_obj.operating_sys.lower()):
                        continue

                if search_device_type != "all" and search_device_type not in host_obj.type:
                    # Using in and not equals because computer can be also local_computer
                    continue

                if self.show_flagged_only_cb.isChecked() and not host_obj.flagged:
                    continue

                if host_obj.type == "router":
                    router_obj = host_obj
                    print("ROUTER IS VALID IN SEARCH:::", router_obj)
                else:
                    valid_hosts_widgets.append(host_widget)

            self.load_topology_view(valid_hosts_widgets, router_obj, False)

        except Exception as e:
            print("ERROR ON SEARCH FUNC:::", e)

    def open_ports_query(self, query: str, ports: Tuple[list, list] | None):
        # Query syntax validation
        ports_list = []
        ports_range = []
        query = query.replace(" ", "")
        if not query:
            # If empty query - return true for host that has any open port
            return ports and (ports[0] or ports[1])
        if not query.isdigit():
            if "," in query:
                # Specific syntax (80, 443, ...)
                ports_list = query.split(",")
                if any(map(lambda x: not x.isdigit(), ports_list)):
                    # There is a part that isn't a port number - invalid syntax
                    print("INVALID PORTS LIST SYNTAX (,) not all are digits")
                    self.search_bar_lineEdit.setStyleSheet("border: 1px solid red; font: 10pt 'Segoe UI';")
                    return
            elif "-" in query:
                # Range syntax (100 - 200)
                ports_range = query.split("-")
                if not len(ports_range) == 2:
                    # Invalid syntax
                    print("INVALID PORTS RANGE SYNTAX (-), more than 1")
                    self.search_bar_lineEdit.setStyleSheet("border: 1px solid red; font: 10pt 'Segoe UI';")
                    return
                if not ports_range[0].isdigit() or not ports_range[1].isdigit():
                    print("INVALID PORTS RANGE SYNTAX (-), not digits")
                    self.search_bar_lineEdit.setStyleSheet("border: 1px solid red; font: 10pt 'Segoe UI';")
                    return
                if int(ports_range[0]) > int(ports_range[1]):
                    print(ports_range)
                    print("INVALID PORTS RANGE SYNTAX (-), left is larger than right")
                    self.search_bar_lineEdit.setStyleSheet("border: 1px solid red; font: 10pt 'Segoe UI';")
                    return

        # Now search for ports
        if not ports:
            print("NO PORTS IN SEARCH - ", ports)
            return False

        # Returning True when found an open port that was listed in the search query
        if ports_list:
            for port in ports_list:
                if (int(port) in ports[0]) or (int(port) in ports[1]):
                    return True
        elif ports_range:
            ports_range_obj = range(int(ports_range[0]), int(ports_range[1]) + 1)
            print("PORTS RANGE:::", ports_range_obj)
            for open_port in ports[0]:
                print("PORTS[0]:::", ports[0])
                if open_port in ports_range_obj:
                    return True
            for open_port in ports[1]:
                if open_port in ports_range_obj:
                    return True
        else:
            # Specific port
            if (int(query) in ports[0]) or (int(query) in ports[1]):
                return True

    def handle_cancel_search_button(self):
        self.search_bar_lineEdit.clear()
        self.device_type_search_comboBox.setCurrentIndex(0)
        self.show_flagged_only_cb.setChecked(False)
        self.handle_search_in_topology()

    def clear_prog_bar_after_scan(self):
        """
        Called by the timer (after delay) to reset the progress bar value.
        :return:
        """
        # TODO - Add status bar text (?)
        if self.scan_prog_bar.value() == self.scan_prog_bar.maximum():
            self.scan_prog_bar.setValue(0)
        self.finished_timer.stop()

    def add_row_to_online_table(self, ip_addr: str, hostname: str):
        """
        Adds a host entry to the Online Hosts table.
        :param ip_addr:
        :param hostname:
        :return:
        """
        if ip_addr in self.online_hosts_table_address_to_row.keys():
            # The IP address is already displayed in the table - change only the hostname part incase there was a change
            if hostname:
                hostname_item = QTableWidgetItem(hostname)
                hostname_item.setToolTip(hostname)  # hostname tooltip (mouse hover)
                self.hosts_table_widget.setItem(self.online_hosts_table_address_to_row[ip_addr], 1, hostname_item)
            return

        if hostname == "":
            hostname = "N/A"
        current_row = self.hosts_table_widget.rowCount()

        self.hosts_table_widget.insertRow(current_row)

        # Set items in each column for the new row
        self.hosts_table_widget.setItem(current_row, 0, QTableWidgetItem(ip_addr))
        hostname_item = QTableWidgetItem(hostname)
        hostname_item.setToolTip(hostname)  # hostname tooltip (mouse hover)
        self.hosts_table_widget.setItem(current_row, 1, hostname_item)
        # Scroll the table to the bottom
        self.hosts_table_widget.scrollToItem(hostname_item)
        self.online_hosts_table_address_to_row[ip_addr] = current_row

    def remove_row_from_table(self, ip_addr: str):
        """
        Function called when a host was found as no longer online by a later scan.
        :return:
        """
        row = self.online_hosts_table_address_to_row.get(ip_addr)
        if row:
            self.hosts_table_widget.removeRow(row)

    def host_click_connect(self, host_obj, host_widg=None):
        for host_widget in self.hosts_widgets_list:
            # Make all other hosts widgets not selected colored
            if host_widget == host_widg:
                continue
            host_widget.border_color = None
            host_widget.update()

        if not host_obj or not host_obj.ip_address:
            return self.host_info_label.setText("No information available.")
        hostname = host_obj.hostname
        hostname_str = f"Hostname: {hostname}<br>" if hostname else ""
        res_time = host_obj.response_time
        latency_str = f"Latency (ping): {res_time}ms<br>" if res_time != -1 else ""
        mac_addr = host_obj.mac_address
        mac_str = f"MAC Address: {mac_addr}<br>" if mac_addr and mac_addr != "N/A" else ""
        info_str = f"<u><b>{host_obj.ip_address} Information:</b></u><br>" \
                   f"{hostname_str}{latency_str}{mac_str}<br>" \
                   f"<font size='1'>(Double click the host to open managing window)</font>"

        self.host_info_label.setText(info_str)

    def show_host_information(self, host) -> None:
        """
        Opens the host info and management window (host double-clicked)
        :param host: The host obj
        :return:
        """
        # THIS OPENS A NEW WINDOW (HOST DOUBLE CLICK CONNECTED FUNCTION)

        info_window = HostInformationWindow(host)
        host.information_window = info_window
        self.host_info_window_created_signal.emit(host)

        if not host.information_window.title_label.text() == "No information available":
            host.information_window.well_known_port_scan_button.clicked.connect(lambda: self.handle_fp_buttons_click(0, host))
            host.information_window.full_port_scan_button.clicked.connect(lambda: self.handle_fp_buttons_click(1, host))
            host.information_window.os_detection_scan_button.clicked.connect(lambda: self.handle_fp_buttons_click(2, host))

            host.information_window.host_clear_fp_scans_queue_tb.clicked.connect(lambda:
                                                                               self.host_clear_fp_scans_queue_signal
                                                                               .emit(host))
            host.information_window.host_cancel_fp_scan_tb.clicked.connect(lambda:
                                                                         self.host_stop_fp_scan_signal
                                                                         .emit(host))
            host.information_window.host_ports_advanced_tb.clicked.connect(lambda:
                                                                    self.host_open_advanced_port_win_signal
                                                                    .emit(host))

        host.information_window.show()

    def handle_fp_buttons_click(self, scan_index: int, host_obj: object):
        if scan_index == 0:
            # Well-known port scan
            host_obj.information_window.well_known_port_scan_button.setDisabled(True)
            self.port_scan_button_signal.emit("well-known-ps", host_obj)
        elif scan_index == 1:
            # Full port scan
            confirmation = QMessageBox.question(self, 'Confirmation',
                                                'The full port scan could take some time.\n'
                                                'Are you sure you want to proceed?',
                                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            # Show the info window on screen after the confirmation selection
            host_obj.information_window.showNormal()
            host_obj.information_window.activateWindow()
            if confirmation == QMessageBox.No:
                return
            host_obj.information_window.full_port_scan_button.setDisabled(True)
            self.port_scan_button_signal.emit("full-ps", host_obj)
        else:
            # OS DETECTION
            host_obj.information_window.os_detection_scan_button.setDisabled(True)
            self.os_detection_scan_button_signal.emit(host_obj)

    def handle_fp_scan_progress_signal(self, prog_val: int, max_prog_val: int, host_obj):
        print(f"({host_obj.ip_address})", "CALLED WITH VALUE:", prog_val, "!!!!!!!!!!!")
        try:
            if host_obj.information_window is not None:
                prog_bar = host_obj.information_window.host_fp_scan_progress_bar
                if max_prog_val != prog_bar.maximum():
                    prog_bar.setMaximum(max_prog_val)
                prog_bar.setValue(prog_val)
        except Exception as e:
            print("ERROR TEST EX 2:", e)

    def handle_fp_scan_finished(self, host_obj):
        try:
            if host_obj.information_window is not None:
                host_obj.information_window.host_fp_scan_progress_bar.setValue(0)  # Reset progress bar
                host_obj.information_window.scan_in_progress_label.setText("")  # Reset scan in-progress label
                host_obj.information_window.update_host_information()
            host_widget = self.find_host_widget_from_topology(host_mac_address=host_obj.mac_address)
            if host_widget:
                host_widget.update_device_image()
        except Exception as e:
            print("ERROR ON LINE 396 (VIEW)", e)

    def find_host_widget_from_topology(self, host_ip_address="", host_mac_address=""):
        if host_ip_address:
            return self.network_topology_viewer.ip_addr_to_host_widget_dict.get(host_ip_address)
        if host_mac_address:
            return self.network_topology_viewer.mac_addr_to_host_widget_dict.get(host_mac_address)

    def show_help_window(self, setting_index: int):
        if setting_index == -1:
            help_message = "Should the graphs get updated automatically or stay still.\n" \
                           "It's recomended to disable this setting (make the graphs still) if you want to analyze the graphs."
        elif setting_index == 0:
            # Scan speed - accuracy setting
            help_message = "This setting allows you to set the values of the scan interval and timeout in order to\n" \
                           "control the speed of the scan progress as well as its accuracy.\n\n" \
                           "The faster the scan is, the less accurate it could be and vice versa.\n" \
                           "The faster the scan is, the more detectable the scan is (higher traffic rate).\n\n" \
                           "The Interval value is the amount of seconds to wait between each request packet transmission.\n" \
                           "The Timeout value is the amount of seconds to wait for a response from a host."
        elif setting_index == 1:
            help_message = "This setting allows you to choose your desired scan method.\n" \
                           "You can choose to use either ARP, ICMP or both."
        elif setting_index == 2:
            # Retrieve host scan info setting
            help_message = "This setting sets what information will be retrieved on every host within the scan.\n\n" \
                           "If both options are unchecked, the scan will not retrieve any further\n" \
                           "information rather then a host's availability and IP and MAC addresses."
        elif setting_index == 3:
            # Router setting
            help_message = "When this setting is checked, the analyzer will try and find the network's router address\n" \
                           "and if the router address isn't included within the scan range it will add it to the scan as the router.\n\n" \
                           "If unchecked, the router will not be added to the scan automatically if it's not in the range."
        elif setting_index == 4:
            # Fingerprint setting
            help_message = "When this setting is checked, each discovered host after the discovery scan will be fingerprinted.\n\n" \
                           "If all options are unchecked, no host will be fingerprinted unless requested by the user\n" \
                           "via the host management window accessible by double clicking on a host."
        elif setting_index == 5:
            # UDP ports setting
            help_message = "When this setting is checked, when running a port scan on a host,\n" \
                           "UDP ports will also be scanned as well as TCP.\n\n" \
                           "If unchecked, only TCP ports will be scanned in a port scan.\n\n" \
                           "NOTE: If this setting is checked and multiple port scans are running concurrently,\n" \
                           "it could lead to the application working slowly."

        self.setting_help_win = HelpWindow(help_message)
        self.setting_help_win.show()


class ScanFinishedWindow(QWidget):
    def __init__(self, scan_time: float, scanned_addresses_amount: int, online_hosts: int):
        """
        Initiates the window
        arg: scan time, number of scanned hosts, number of online hosts.
        """
        super().__init__()
        self.setWindowIcon(QIcon(r"src/view/icons/checkmark.png"))
        self.setWindowTitle("Scan Completed!")
        self.setMinimumSize(350, 220)

        self.title_label = QLabel(f"Scan Completed!")
        self.title_label.setFont(QFont("Segoe UI", 18))
        self.title_label.setAlignment(Qt.AlignCenter)

        self.info_label = QLabel(f"Scan took: {format_time(scan_time)}.\n"
                                 f"Scanned {scanned_addresses_amount} {'hosts' if scanned_addresses_amount > 1 else 'host'}\n"
                                 f"Responsive Hosts: {online_hosts}")
        self.info_label.setFont(QFont("Segoe UI", 12))

        self.layout = QVBoxLayout()
        self.layout.addWidget(self.title_label)
        self.layout.addWidget(self.info_label)

        spacer_item = QSpacerItem(0, 15, QSizePolicy.Minimum, QSizePolicy.Minimum)
        self.layout.addSpacerItem(spacer_item)

        self.close_button = QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        self.close_button.setFont(QFont("Segoe UI", 10))
        self.close_button.setCursor(QCursor(QtCore.Qt.PointingHandCursor))
        self.layout.addWidget(self.close_button)

        self.setLayout(self.layout)


def format_time(seconds):
    if seconds < 1:
        return f"{int(seconds * 1000)}ms"
    elif seconds < 60:
        return f"{seconds:.2f}sec"
    else:
        minutes, seconds = divmod(seconds, 60)
        return f"{int(minutes)}min {seconds:.2f}sec"


def query_string(query: str, string: str) -> bool:
    """
    Function queries a string with a given query.
    The function returns True if the query is found in the string or if the query is empty.
    :param query: The query
    :param string: The string to search in
    :return: True or False
    """
    return (not query) or (query in string)
