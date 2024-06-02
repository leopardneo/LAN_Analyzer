"""
Author: Ofir Brovin.
This file is the connector of the LAN Analyzer application.
"""
from __future__ import annotations

import sys
if __name__ == "__main__":
    sys.exit("This file is part of the LAN Analyzer application and cannot be run independently")

import os
import math
import threading
import configparser

from typing import List, Tuple

from PyQt5.QtWidgets import QMessageBox, QFileDialog
from PyQt5.QtCore import QCoreApplication, QTimer

from ..model.network import AnalyzerNetwork
from ..model.packages.host import Host
from ..view import AnalyzerWindow, AdvancedPortsInfoWindow, SendWarningWindow
from ..view import format_time


class LanAnalyzer:
    """
    LAN Analyzer application controller.
    """
    def __init__(self, settings: configparser.ConfigParser):
        """
        Initiates the LAN Analyzer application controller.
        :param settings: ConfigParser object containing the settings for the app.
        """
        self.network_module = AnalyzerNetwork()
        self.view_window = AnalyzerWindow()

        # Network signals
        self.network_module.scan_max_progress_signal.connect(
            lambda amount: self.view_window.scan_prog_bar.setMaximum(amount))
        self.network_module.scan_progress_update_signal.connect(
            lambda amount: self.view_window.scan_prog_bar.setValue(amount))
        # self.network_module.scan_address_result_signal.connect(lambda host: self.view_window.add_row_to_table(
        #     host.ip_address, host.hostname))  # SPECIAL
        self.network_module.scan_address_result_signal.connect(self._handle_host_finished_scan_signal)
        self.network_module.scan_address_no_longer_online_signal.connect(self._handle_host_no_longer_online_signal)
        # ***
        # self.network_module.scan_finished_signal.connect(lambda local_addr, hosts_list, router_host, time, scanned:
        #                                                  self.view_window.scan_finished(local_addr, hosts_list, router_host, time, scanned))
        self.network_module.scan_finished_signal.connect(self._handle_scan_finished_signal)
        # ***
        self.network_module.alert_pop_window_signal.connect(
            lambda mtype, message: self._handle_pop_window_signal(mtype, message))

        # Fingerprint scan signals
        # Fingerprint scan progress update signal
        self.network_module.fp_scan_progress_signal.connect(self.view_window.handle_fp_scan_progress_signal)
        # Fingerprint scan finished signal
        self.network_module.fp_scan_finished_signal.connect(self._handle_host_fp_scan_finished_signal)

        # Modules signals
        # Hosts connector
        # New host connected signal
        self.network_module.new_host_connected_signal.connect(self._handle_new_host_connection_signal)
        # New message signal
        self.network_module.new_message_signal.connect(self._handle_new_message_signal)
        # Connected Host disconnected signal
        self.network_module.connected_host_disconnected_signal.connect(self._handle_connected_host_disconnected_signal)

        # Sniffer
        # Traffic host signal
        self.network_module.sniffer_traffic_signal.connect(self._handle_traffic_host_signal)
        # High traffic host signal
        self.network_module.sniffer_high_traffic_signal.connect(self._handle_high_traffic_host_signal)
        # New traffic host signal
        self.network_module.sniffer_new_traffic_host_detected_signal.connect(self._handle_new_traffic_host_signal)

        # View signals
        self.view_window.scan_interval_finished_signal.connect(self._handle_start_or_stop_network_scan)
        self.view_window.host_info_window_created_signal.connect(
            self.network_module.create_host_fp_scans_prog_update_timer)
        self.view_window.port_scan_button_signal.connect(lambda scan_type, host_obj:
                                                         self._handle_run_host_fp_scan(host_obj, scan_type))
        self.view_window.os_detection_scan_button_signal.connect(
            lambda host_obj: self._handle_run_host_fp_scan(host_obj, self.network_module.OS_DETECTION_SCAN))
        # self.view_window.host_clear_fp_scans_queue_signal.connect(self.handle_clear_host_fp_scans_queue) 26/05
        self.view_window.host_clear_fp_scans_queue_signal.connect(lambda host_obj: host_obj.clear_fp_scans_queue())
        # self.view_window.host_stop_fp_scan_signal.connect(self.handle_stop_host_fp_scan) 26/05
        self.view_window.host_stop_fp_scan_signal.connect(lambda host_obj: host_obj.stop_running_fp_scan())
        self.view_window.host_open_advanced_port_win_signal.connect(self._handle_open_host_advanced_port_win)

        # --- INTERFACES COMBO BOX ---
        # Set placeholder text in the interface combo box
        self.view_window.interfaces_combobox.addItem("Select Network Interface To Scan...")
        self.view_window.interfaces_combobox.model().item(0).setEnabled(False)
        self.view_window.interfaces_combobox.addItem("")
        self.view_window.interfaces_combobox.model().item(1).setEnabled(False)
        # Add interfaces entries
        for interface in self.network_module.network_interfaces:
            self.view_window.interfaces_combobox.addItem(
                f"{interface.name} - {interface.description} ({interface.cidr_notation})")

        # Link interfaces combo box entry select
        self.view_window.interfaces_combobox.activated.connect(
            lambda index: self._handle_interfaces_combobox_change(index))
        # --- ---

        self.view_window.start_scan_button.clicked.connect(self._handle_start_or_stop_network_scan)
        # Online hosts table widget connect
        self.view_window.hosts_table_widget.cellClicked.connect(
            lambda row, col: self._handle_host_table_single_click(row))
        self.view_window.hosts_table_widget.cellDoubleClicked.connect(
            lambda row, col: self._handle_host_table_double_click(row))
        self.first_scan: bool = True

        # CONNECTED HOSTS
        self.currently_selected_connected_host: Tuple[str, int] | None = None  # Stores the addr of the selected host
        # Allow new connections checkbox connect
        self.view_window.allow_new_hosts_connections_checkbox.stateChanged.connect(self._handle_hosts_connector_checkbox)
        # Connected host clicked from list widget connect
        self.view_window.connected_hosts_listWidget.itemClicked.connect(self._handle_connected_host_clicked)
        # Disconnect Host button connect
        self.view_window.disconnect_host_button.clicked.connect(self._handle_disconnect_host_button)
        # Flag Host button connect
        self.view_window.flag_host_button.clicked.connect(self._handle_flag_button)
        # Information Window button connect
        self.view_window.info_win_button.clicked.connect(self._handle_information_window_button)
        # Send a file button connect
        self.view_window.send_file_button.clicked.connect(self._handle_send_file_to_host)
        # Send a warning button connect
        self.view_window.send_warning_button.clicked.connect(self._handle_send_warning_to_host)
        # Clear chat button connect
        self.view_window.clear_host_chat_button.clicked.connect(self._handle_clear_host_chat)
        # Send message to connected host button connect
        self.view_window.send_button.clicked.connect(self._handle_send_message_to_connected_host)
        # Enter press in message lineedit connect
        self.view_window.message_lineEdit.returnPressed.connect(self._handle_send_message_to_connected_host)

        # TRAFFIC SNIFFER
        # Host clicked from (traffic) hosts list widget
        self.view_window.sniffer_hosts_list_widget.itemClicked.connect(self._handle_host_clicked_in_traffic_sniffer)
        self.view_window.update_traffic_graphs_auto_cb.stateChanged.connect(
            self._handle_update_traffic_graphs_setting_cb_change)
        self.traffic_graphs_update_timer: QTimer | None = None

        # Save settings button connect
        self.view_window.save_settings_button.clicked.connect(self._handle_save_settings)

        # Exit sidebar button(s) connect
        self.view_window.exit_button_1.clicked.connect(self._handle_exit)
        self.view_window.exit_button_2.clicked.connect(self._handle_exit)

        self._apply_settings(settings=settings)

        self.view_window.show()

    def _handle_interfaces_combobox_change(self, index) -> None:
        """
        Handles interface selection from the combobox change.
        :param index: The current index of the selected interface.
        :return: None
        """
        self.network_module.selected_interface(index - 2)
        self.view_window.handle_interfaces_combobox_change(self.network_module.scan_addresses[0],
                                                           self.network_module.scan_addresses[-1])

    def _handle_start_or_stop_network_scan(self) -> None:
        """
        Handles the "Start Scan" button click - start or stop the scan.
        Also called to start the scan when the scan interval timer runs out.
        Updates the window to the matching scan state and performs the network scan process.
        :return: None
        """
        try:
            if self.view_window.start_scan_button.text() == "Start Scan":
                try:
                    self.view_window.scan_start()
                    # Checking the scan method from the settings
                    if self.view_window.arp_scan_method_radio_button.isChecked():
                        # ARP Only
                        scan_method = "ARP"
                    elif self.view_window.icmp_scan_method_radio_button.isChecked():
                        # ICMP Ping only
                        scan_method = "ICMP"
                    else:
                        # Scan using both ARP and ICMP
                        scan_method = "BOTH"

                    # Start network module scan process thread
                    scan_thread = threading.Thread(target=self.network_module.start_scanning_network,
                                                   args=(self.view_window.start_ip_line.text(),
                                                         self.view_window.end_ip_line.text(),
                                                         scan_method,
                                                         self.view_window.interval_setting_spinbox.value(),
                                                         self.view_window.timeout_setting_spinbox.value(),
                                                         self.view_window.router_setting_switch.isChecked(),
                                                         self.view_window.retrieve_hostname_setting_switch.isChecked(),
                                                         self.view_window.retrieve_res_time_setting_switch.isChecked()))
                    scan_thread.daemon = True
                    scan_thread.start()
                    # Add event to logger
                    self.view_window.logger.add_event(event_message=f"Scan started.",
                                                      event_type=self.view_window.logger.SCAN_STARTED_EVENT_TYPE)
                except Exception as e:
                    print("ERROR occurred on start scan function:", e)
            else:
                # Stop scan pressed
                self.view_window.start_scan_button.setDisabled(True)
                self.view_window.start_scan_button.setText("Stopping Scan...")
                self.network_module.scanner.set_stop_scan(value=True)  # Set the stop flag in the network scanner
        except Exception as eee:
            print("ERROR THERE WAS ERROR ON STARTING / STOPPING THE SCAN!!!:", type(eee), eee)

    def _handle_host_finished_scan_signal(self, host: Host) -> None:
        """
        Function called when a single host has finished being discovered in the scan.
        If the scans in the "Automatically fingerprint each responsive host" setting are checked,
        it will start these fingerprinting scans for that host.
        :param host: The Host object.
        :return: None
        """
        # Add event to logger (adding before running and logging fp scan)
        self.view_window.logger.add_event(event_message=f"{host.ip_address} discovered online in the scan",
                                          event_type=self.view_window.logger.MID_SCAN_RESULT_EVENT_TYPE)
        # Fingerprinting scans
        if self.view_window.well_known_port_scan_fp_setting_switch.isChecked():
            # Start well-known port scan
            self._handle_run_host_fp_scan(host, self.network_module.WELL_KNOWN_PORT_SCAN)
        elif self.view_window.full_port_scan_fp_setting_switch.isChecked():
            # Start full port scan
            self._handle_run_host_fp_scan(host, self.network_module.FULL_PORT_SCAN)
        if self.view_window.os_detection_fp_setting_switch.isChecked():
            # Start full port scan
            self._handle_run_host_fp_scan(host, self.network_module.OS_DETECTION_SCAN)

        # Add the host entry to the online hosts table
        self.view_window.add_row_to_online_table(host.ip_address, host.hostname)

    def _handle_host_no_longer_online_signal(self, host_ip_addr: str) -> None:
        """
        Handles the host no longer online signal emitted by the scanner in the network module.
        The signal is emitted when a host was discovered as online in a previous scan but now is no longer online.
        :param host_ip_addr: The offline host IP address.
        :return: None
        """
        try:
            print("handle_host_no_longer_online_signal CALLED for:::", host_ip_addr)
            self.view_window.remove_row_from_table(ip_addr=host_ip_addr)

            host_obj = self.network_module.get_host_obj(host_ip_addr=host_ip_addr)
            # Close the host info win of the offline host if its opened
            if host_obj.information_window is not None:
                host_obj.information_window.close()
                host_obj.information_window = None
            # Clear fp scans queue and stop the current working one if there is.
            host_obj.fp_scans_queue.clear()
            if host_obj.fp_scan_in_progress:
                with host_obj.stop_fp_scan_flag_lock:
                    host_obj.stop_fp_scan_flag.set()

            # Delete references saved in the network module to the host.
            saved_host_obj_mac_addr = host_obj.mac_address
            if saved_host_obj_mac_addr in self.network_module.mac_to_host_obj_dict.keys():
                del self.network_module.mac_to_host_obj_dict[saved_host_obj_mac_addr]
            del self.network_module.ip_to_host_obj_dict[host_ip_addr]
            # Add event to logger
            # TODO - add this event ?
            self.view_window.logger.add_event(event_message=f"{host_ip_addr} discovered no longer online in the scan",
                                              event_type=self.view_window.logger.MID_SCAN_RESULT_EVENT_TYPE)

        except Exception as e:
            print("ERROR IN handle_host_no_longer_online_signal (main):::", e)

    def _handle_scan_finished_signal(self, hosts_list: List[Host], router_host: Host, time_taken: float, scanned: int) -> None:
        """
        Handles the scan finished signal.
        Function is called when scanning the network has completed - set the window state to normal (no scan),
        Create the network topology viewer and if it's the first scan run, enable the sniffer and the hosts connector.
        :param hosts_list: Online Hosts list.
        :param router_host: The network's router Host.
        :param time_taken: The time taken for the scan process to finish.
        :param scanned: How many addresses were scanned.
        :return: None
        """
        try:
            self.view_window.scan_finished(hosts_list, router_host, time_taken, scanned)
            # If there is any search filter applied - do the search for the new topology
            self.view_window.handle_search_in_topology()
            # Update sniffer vars (for the filter)
            self.network_module.sniffer.set_mac_addresses(self.network_module.mac_to_host_obj_dict.keys())
            self.network_module.sniffer.set_ip_addresses(self.network_module.ip_to_host_obj_dict.keys())
            if self.first_scan:
                self.first_scan = False
                # Setting up modules:
                # Hosts Connector
                self.network_module.hosts_connector.init_connector()  # local addr already defined by scan in the network
                self.view_window.mark_hosts_connector_as_open(self.network_module.hosts_connector.listening_sock_addr)
                # Sniffer
                self.network_module.sniffer.start_sniffing()
                self.view_window.mark_sniffer_as_open()
            # Add event to logger
            self.view_window.logger.add_event(event_message=f"Scan finished.\n"
                                                            f"Scan took {format_time(time_taken)}.\n"
                                                            f"{len(hosts_list) + (1 if router_host.ip_address else 0)} hosts discovered.",
                                              event_type=self.view_window.logger.SCAN_FINISHED_EVENT_TYPE)
        except Exception as e:
            print("ERROR ON SCAN FINISHED SIGNAL MAIN HANDLING:::", e)

    def _handle_host_table_single_click(self, row) -> None:
        """
        Handles single click on a host from the online hosts table.
        Shows information in the right label about the selected host.
        :param row: The row of the clicked host item.
        :return: None
        """
        try:
            item = self.view_window.hosts_table_widget.item(row, 0)
            if item is None:
                return
            host_obj = self.network_module.get_host_obj(host_ip_addr=item.text())
            self.view_window.host_click_connect(host_obj)
        except Exception as e:
            print("ERROR EXCEPTION ON CLICK", e)

    def _handle_host_table_double_click(self, row) -> None:
        """
        Handles double click on a host from the online hosts table.
        Opens the host information and management window of that host.
        :param row: The row of the (double) clicked host item.
        :return: None
        """
        try:
            item = self.view_window.hosts_table_widget.item(row, 0)
            if item is None:
                return
            host_obj = self.network_module.get_host_obj(item.text())
            self.view_window.show_host_information(host_obj)
        except Exception as e:
            print("ERROR EXCEPTION ON DOUBLE CLICK:", e)

    def _handle_run_host_fp_scan(self, host_obj: Host, scan_type) -> None:
        """
        Handles running fingerprint scan on a host.
        Checks if the host has no fingerprint scan running, and starts the fp scan if so, and if there is a fingerprint
        scan in progress, adds the wanted scan to the fingerprint scans queue.
        Updates the host's information and management window fp scans section if it's opened.
        :param host_obj: The (target) Host object.
        :param scan_type: The wanted fingerprint scan type (network_module.OS_DETECTION_SCAN / ...)
        :return: None
        """
        try:
            if host_obj.fp_scan_in_progress:
                if scan_type not in host_obj.fp_scans_queue and scan_type != host_obj.current_fp_scan:
                    # Add the scan only if it's not currently doing that scan and if it's not already in the queue
                    print(f"FP SCAN IS IN PROGRESS!! ADDING SCAN TO QUEUE OF {host_obj.ip_address}:", scan_type)
                    host_obj.fp_scans_queue.append(scan_type)
            else:
                # No fp scan in progress - run the wanted one.
                print(f"NO FP SCAN IN PROG, STARTING FP SCAN FOR {host_obj.ip_address}:", scan_type)
                self.network_module.run_fp_scan(host_obj, scan_type,
                                                self.view_window.scan_udp_ports_setting_switch.isChecked(),
                                                self.view_window.timeout_setting_spinbox.value())
                # Add event to logger
                self.view_window.logger.add_event(
                    event_message=f"Started {host_obj.current_fp_scan_str} on {host_obj.ip_address}",
                    event_type=self.view_window.logger.FP_SCAN_EVENT_TYPE)

            if host_obj.information_window is not None:
                host_obj.information_window.update_fp_scans_section()
        except Exception as e:
            print("ERROR (_handle_run_host_fp_scan)", e)

    def _handle_host_fp_scan_finished_signal(self, host_obj: Host) -> None:
        """
        Handles the host has finished a fingerprint scan signal from the network module.
        :param host_obj: The Host object.
        :return: None
        """
        print(f"handle_host_fp_scan_finished_signal called - {host_obj.ip_address} finished fp scan!")
        # Add event to logger before clearing vars
        self.view_window.logger.add_event(
            event_message=f"{host_obj.current_fp_scan_str} on {host_obj.ip_address} has finished!",
            event_type=self.view_window.logger.FP_SCAN_EVENT_TYPE)

        host_obj.current_fp_scan_str = ""
        host_obj.fp_scan_in_progress = False
        host_obj.current_fp_scan = ""
        with host_obj.stop_fp_scan_flag_lock:
            host_obj.stop_fp_scan_flag.clear()

        # Update the host information and management window (if it's opened) and update device image.
        self.view_window.handle_fp_scan_finished(host_obj)

        # If the host has more fp scans in the queue, run the first one.
        if host_obj.fp_scans_queue:
            self._handle_run_host_fp_scan(host_obj, host_obj.fp_scans_queue.pop(0))



    def _handle_open_host_advanced_port_win(self, host_obj: Host) -> None:
        """
        Opens the advanced ports information window for a host.
        Called when user clicks on the open advanced button in the host info and management window.
        :param host_obj: The host object.
        :return: None
        """
        try:
            if not host_obj.open_ports:
                return

            # TCP ports
            open_tcp_ports = host_obj.open_ports[0]
            open_tcp_ports_and_services_list = []
            open_tcp_ports_length = len(open_tcp_ports)
            if open_tcp_ports:
                open_tcp_ports_and_services_list: List[str] = self._get_ports_and_services_list(open_tcp_ports, "TCP")

            closed_tcp_ports_and_services_list = []
            closed_tcp_ports_length = 0
            if host_obj.closed_ports:
                closed_tcp_ports = host_obj.closed_ports[0]
                closed_tcp_ports_length = len(closed_tcp_ports)
                if closed_tcp_ports and closed_tcp_ports_length <= 10:
                    closed_tcp_ports_and_services_list: List[str] = self._get_ports_and_services_list(closed_tcp_ports,
                                                                                                     "TCP")

            filtered_tcp_ports_and_services_list = []
            filtered_tcp_ports_length = 0
            if host_obj.filtered_ports:
                filtered_tcp_ports = host_obj.filtered_ports[0]
                filtered_tcp_ports_length = len(filtered_tcp_ports)
                if filtered_tcp_ports and filtered_tcp_ports_length <= 10:
                    filtered_tcp_ports_and_services_list: List[str] = self._get_ports_and_services_list(
                        filtered_tcp_ports, "TCP")

            # UDP ports
            udp_scanned = (
                    len(host_obj.open_ports[1]) > 0 or
                    len(host_obj.closed_ports[1]) > 0 or
                    len(host_obj.filtered_ports[1]) > 0
            )
            if not udp_scanned:
                open_udp_ports_length = 0
                open_udp_ports_and_services_list = []
                closed_udp_ports_and_services_list = []
                closed_udp_ports_length = 0
                filtered_udp_ports_and_services_list = []
                filtered_udp_ports_length = 0
            else:
                open_udp_ports = host_obj.open_ports[1]
                open_udp_ports_and_services_list = []
                open_udp_ports_length = len(open_udp_ports)
                if open_udp_ports:
                    open_udp_ports_and_services_list: List[str] = self._get_ports_and_services_list(open_udp_ports,
                                                                                                   "UDP")

                closed_udp_ports_and_services_list = []
                closed_udp_ports_length = 0
                if host_obj.closed_ports:
                    closed_udp_ports = host_obj.closed_ports[1]
                    closed_udp_ports_length = len(closed_udp_ports)
                    if closed_udp_ports and closed_udp_ports_length <= 10:
                        closed_udp_ports_and_services_list: List[str] = self._get_ports_and_services_list(
                            closed_udp_ports,
                            "UDP")

                filtered_udp_ports_and_services_list = []
                filtered_udp_ports_length = 0
                if host_obj.filtered_ports:
                    filtered_udp_ports = host_obj.filtered_ports[1]
                    filtered_udp_ports_length = len(filtered_udp_ports)
                    if filtered_udp_ports and filtered_udp_ports_length <= 10:
                        filtered_udp_ports_and_services_list: List[str] = self._get_ports_and_services_list(
                            filtered_udp_ports, "UDP")

            host_obj.advanced_ports_window = AdvancedPortsInfoWindow(open_tcp_ports_length + open_udp_ports_length,
                                                                     open_tcp_ports_and_services_list,
                                                                     open_tcp_ports_length,
                                                                     closed_tcp_ports_and_services_list,
                                                                     closed_tcp_ports_length,
                                                                     filtered_tcp_ports_and_services_list,
                                                                     filtered_tcp_ports_length,
                                                                     udp_scanned,
                                                                     open_udp_ports_and_services_list,
                                                                     open_udp_ports_length,
                                                                     closed_udp_ports_and_services_list,
                                                                     closed_udp_ports_length,
                                                                     filtered_udp_ports_and_services_list,
                                                                     filtered_udp_ports_length,
                                                                     )
            host_obj.advanced_ports_window.show()
        except Exception as e:
            print("ERROR IN HANDLE OPEN ADVANCED PORTS INFO WIN:::", e)

    def _get_ports_and_services_list(self, ports_list: List[int], protocol: str) -> List[str]:
        """
        Returns a list of strings containing the ports and its service ["• {port} - {port's_service}", ...]
        :param ports_list: The ports list (ints)
        :param protocol: The port's service protocol (TCP / UDP)
        :return: The list of strings with the ports and their related service of the given protocol.
        """
        ports_with_services_list: List[str] = []
        if self.network_module.port_service_lookup is None:
            ports_with_services_list.append("[ Ports services module data file is missing. ]")
        for port in ports_list:
            if self.network_module.port_service_lookup is None:
                ports_with_services_list.append(f"• {port}")
            else:
                ports_with_services_list.append(
                    f"• {port} - {self.network_module.port_service_lookup.lookup_service(port, protocol)}")

        return ports_with_services_list

    @staticmethod
    def _handle_pop_window_signal(message_type: str, message: str) -> None:
        """
        Handles the show pop-up window message (warning) signal.
        Opens a pop-up message window with the given message and the message type (warning / error).
        :param message_type: The message type ["WARNING", "ERROR"]
        :param message: The message text.
        :return: None
        """
        msg = QMessageBox()
        msg.setText(message)
        msg.setStandardButtons(QMessageBox.Ok)
        if message_type == "WARNING":
            msg.setIcon(QMessageBox.Warning)
            msg.setWindowTitle("Warning")
        elif message_type == "ERROR":
            msg.setIcon(QMessageBox.Critical)
            msg.setWindowTitle("Error")
        msg.exec_()

    # ------ HOSTS CONNECTOR FUNCTIONS ------
    def _handle_hosts_connector_checkbox(self, state) -> None:
        """
        Handles the checkbox click whether to allow new connections to the hosts connector or not.
        :param state: The new state of the setting checkbox.
        :return: None
        """
        if state == 2:
            # The Checkbox is now checked
            if self.network_module.hosts_connector.socket_open:
                self.network_module.hosts_connector.set_allow_new_connections(new_state=True)
                self.view_window.mark_hosts_connector_as_open(self.network_module.hosts_connector.listening_sock_addr)
            else:
                self._handle_pop_window_signal("ERROR", "The hosts connector module socket is closed for some reason.\n"
                                                        "Please consider re-running the application and trying again.")
        elif state == 0:
            # The Checkbox is now not checked
            self.network_module.hosts_connector.set_allow_new_connections(new_state=False)
            self.view_window.mark_hosts_connector_as_not_accepting()

    def _handle_connected_host_clicked(self, host_item) -> None:
        """
        Handles selection of a connected host from the connected hosts list.
        Loads the host chat and applies the screen.
        :param host_item: The selected host item.
        :return: None
        """
        if host_item is None:
            return
        host_addr_item_str = host_item.text()
        host_addr_tuple: Tuple[str, int]
        if "-" in host_addr_item_str:
            temp = host_addr_item_str.split("-")[0].replace(" ", "").split(":")
            host_addr_tuple = temp[0], int(temp[1])
        else:
            temp = host_addr_item_str.replace(" ", "").split(":")
            host_addr_tuple = temp[0], int(temp[1])

        try:
            self.currently_selected_connected_host = host_addr_tuple
            chat_history = self.network_module.hosts_connector.get_chat_history(host_addr_tuple)
            self.view_window.load_host_chat(host_addr_tuple, chat_history)
        except Exception as e:
            print("ERROR occurred on handle_connected_host_clicked (controller.py):::", e)

    def _handle_disconnect_host_button(self) -> None:
        """
        Handles the "disconnect host" connected host button.
        Disconnects the host.
        :return: None
        """
        curr_host = self.currently_selected_connected_host
        if curr_host:
            self.network_module.hosts_connector.disconnect_user(self.network_module.hosts_connector
                                                                .get_user_socket_by_addr(curr_host))

    def _handle_flag_button(self) -> None:
        """
        Handles the "flag host" connected host button.
        Flags / removes flag from the host. (If the host exists in the topology)
        :return: None
        """
        curr_host = self.currently_selected_connected_host
        if curr_host:
            host_widget = self.view_window.find_host_widget_from_topology(host_ip_address=curr_host[0])
            if host_widget:
                if host_widget.host_obj.flagged:
                    flag = False
                    new_text = "Flag Host"
                else:
                    flag = True
                    new_text = "Remove Flag"
                host_widget.set_flagged(flag)
                self.view_window.flag_host_button.setText(new_text)
            else:
                self._handle_pop_window_signal("WARNING",
                                               "Could not find a widget for this host in the scanner topology.\n"
                                               "Please make sure this host is scanned and try again.")

    def _handle_information_window_button(self) -> None:
        """
        Handles the "information window" connected host button.
        Opens the host information window for that host. (If the host was scanned)
        :return: None
        """
        curr_host = self.currently_selected_connected_host
        if curr_host:
            ip_addr = curr_host[0]
            host_obj = self.network_module.get_host_obj(ip_addr)
            self.view_window.show_host_information(host_obj)

    def _handle_send_file_to_host(self) -> None:
        """
        Handles the "send a file" connected host button.
        Opens a file dialog to allow the user to select a file and sends it to the connected host.
        :return: None
        """

        def convert_file_size_to_readable(size_in_bytes: int):
            """
            Converts a file size in bytes to a human-readable string.
            :param size_in_bytes: The file size in bytes.
            :return: The file size in a human-readable string.
            """
            if size_in_bytes == 0:
                return "0B"

            size_names = ("B", "KB", "MB", "GB", "TB", "PB")
            i = int(math.floor(math.log(size_in_bytes, 1024)))
            p = math.pow(1024, i)
            s = round(size_in_bytes / p, 2)
            return f"{s} {size_names[i]}"

        target_host_addr = self.currently_selected_connected_host
        file_dialog = QFileDialog()
        if file_dialog.exec_():
            # File was selected
            file_full_path = file_dialog.selectedFiles()[0]
            file_name = os.path.basename(file_full_path)
            file_size = os.path.getsize(file_full_path)
            confirmation = QMessageBox.question(self.view_window, "Confirmation", f"Sending {file_name} "
                                                                  f"({convert_file_size_to_readable(file_size)}) "
                                                                  f"to {target_host_addr[0]}:{target_host_addr[1]}",
                                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if confirmation == QMessageBox.No:
                return
            print("SELECTED FILE:::", file_name, "SIZE:::", file_size)
            with open(file_full_path, "rb") as file:
                self.network_module.hosts_connector.send_file(file, file_name, target_host_addr)
            print("File transfer COMPLETE")

    def _handle_send_warning_to_host(self) -> None:
        """
        Handles the "send a warning" connected host button.
        Opens the send warning window to allow to user to send his wanted warning to the connected host.
        Links the send warning button in the warning window to the network send message function
        :return: None
        """
        try:
            target_host = self.currently_selected_connected_host
            target_host_obj = self.network_module.get_host_obj(host_ip_addr=target_host[0])
            if target_host_obj:
                target_host_obj.warning_window = SendWarningWindow(warning_dest_host_obj=target_host_obj)

                target_host_obj.warning_window.send_warning_button.clicked.connect(lambda:
                                                                                   self.network_module.hosts_connector.send_message(
                                                                                       target_host_obj.warning_window.warning_plainTextEdit.toPlainText(),
                                                                                       target_host_obj.warning_window.warning_type_comboBox.currentText().upper(),
                                                                                       target_host))

                target_host_obj.warning_window.show()
            else:
                # Use the view window as a holder for the window for not scanned connected hosts.
                self.view_window.warning_window = SendWarningWindow(warning_dest_ip_addr=target_host[0])

                self.view_window.warning_window.send_warning_button.clicked.connect(lambda:
                                                                                   self.network_module.hosts_connector.send_message(
                                                                                       self.view_window.warning_window.warning_plainTextEdit.toPlainText(),
                                                                                       self.view_window.warning_window.warning_type_comboBox.currentText().upper(),
                                                                                       target_host))

                self.view_window.warning_window.show()
        except Exception as e:
            print("ERROR OCCURRED WHEN GENERATING WARNING SCREEN WINDOW:::", e)

    def _handle_clear_host_chat(self) -> None:
        """
        Handles the "clear chat" connected host button.
        Clears the host's chat and deletes from the DB.
        :return: None
        """
        target_host = self.currently_selected_connected_host
        if target_host:
            self.network_module.hosts_connector.clear_host_chat(target_host)
            self.view_window.load_host_chat(target_host,
                                            self.network_module.hosts_connector.get_chat_history(target_host))

    def _handle_send_message_to_connected_host(self) -> None:
        """
        Handles sending a message to a connected host.
        Called when send button is pressed or when enter is pressed within the message entry.
        Sends the message to the host (regular message type).
        :return: None
        """
        try:
            text = self.view_window.message_lineEdit.text()
            curr_host = self.currently_selected_connected_host
            if text and curr_host:
                self.network_module.hosts_connector.send_message(text, "REGULAR", curr_host)
                self.view_window.message_lineEdit.clear()
        except Exception as e:
            print("ERROR ON SEND MESSAGE:", e)

    # Hosts Connector SIGNALS handling functions
    def _handle_new_host_connection_signal(self, sock_addr: Tuple[str, int]) -> None:
        """
        Handles the new connected host (host has connected) signal.
        Logs the event to logger.
        :param sock_addr: The connected host socket address [IP, port]
        :return: None
        """
        host_obj = self.network_module.get_host_obj(sock_addr[0])
        if host_obj:
            host_obj.script_connected = True
        hostname = host_obj.hostname if host_obj else ""
        self.view_window.add_host_to_connected_list_widget(sock_addr, hostname)
        # Add connected icon
        host_widget = self.view_window.find_host_widget_from_topology(host_ip_address=sock_addr[0])
        if host_widget:
            host_widget.set_connected_icon(True)
        # Add event to logger
        self.view_window.logger.add_event(event_message=f"{sock_addr[0]} has connected via the script.",
                                          event_type=self.view_window.logger.CONNECTED_HOST_CONNECTED_EVENT_TYPE)

    def _handle_connected_host_disconnected_signal(self, host_addr: Tuple[str, int]) -> None:
        """
        Handles the connected host has disconnected signal.
        Logs the event to logger.
        :param host_addr: The (no longer) connected host socket address [IP, port]
        :return: None
        """
        try:
            self.view_window.remove_host_from_connected_list_widget(host_addr)
            # If the disconnected host is the current selected one, apply changes to the screen
            if self.currently_selected_connected_host == host_addr:
                self.view_window.chat_listWidget.addItem("Host has disconnected.")
                self.view_window.chat_frame.setDisabled(True)
                self.view_window.tools_frame.setDisabled(True)
                self.view_window.disconnect_host_button.setDisabled(True)
                self.view_window.flag_host_button.setDisabled(True)
                self.view_window.info_win_button.setDisabled(True)
            # Remove connected icon
            host_widget = self.view_window.find_host_widget_from_topology(host_ip_address=host_addr[0])
            if host_widget:
                host_widget.set_connected_icon(False)
            host_obj = self.network_module.get_host_obj(host_addr[0])
            if host_obj:
                host_obj.script_connected = False
                if host_obj.warning_window is not None:
                    host_obj.warning_window.close()
                    host_obj.warning_window = None
            # Add event to logger
            self.view_window.logger.add_event(event_message=f"{host_addr[0]} in no longer connected via the script.",
                                              event_type=self.view_window.logger.CONNECTED_HOST_DISCONNECTED_EVENT_TYPE)
        except Exception as e:
            print("ERROR WHILE REMOVING HOST:", e)

    def _handle_new_message_signal(self, message_host: Tuple[str, int]) -> None:
        """
        Handles the new message (from or to) a connected host signal.
        Logs the event to logger.
        # TODO - logs message when sent and also when received! (change that?)
        :param message_host: The message's connected host socket address [IP, port]
        :return: None
        """
        print("MESSAGE HOST:", message_host, type(message_host))
        print("CURRENT HOST:", self.currently_selected_connected_host, type(self.currently_selected_connected_host))
        if self.currently_selected_connected_host == message_host:  # Address of the new message is the selected host?
            # Update the chat
            self.view_window.load_host_chat(message_host,
                                            self.network_module.hosts_connector.get_chat_history(message_host))
        # Add event to logger
        self.view_window.logger.add_event(
            event_message=f"New message with connected host: {message_host[0]}:{message_host[1]}",
            event_type=self.view_window.logger.CONNECTED_HOST_NEW_MESSAGE_EVENT_TYPE)

    # ------ TRAFFIC SNIFFER FUNCTIONS ------
    def _handle_host_clicked_in_traffic_sniffer(self, traffic_host_item) -> None:
        """
        Handles selection of a traffic host from the traffic sniffer hosts list.
        Loads the host's traffic graphs and start the auto updates timer if the auto update graphs setting is checked.
        :param traffic_host_item: The selected traffic host item.
        :return: None
        """
        try:
            if traffic_host_item is None:
                return
            if self.traffic_graphs_update_timer and self.traffic_graphs_update_timer.isActive():
                self.traffic_graphs_update_timer.stop()
                self.traffic_graphs_update_timer = None

            self.view_window.traffic_rate_graphs_title_label.setEnabled(True)
            self.view_window.traffic_rate_graphs_title_label.setText(f"{traffic_host_item.text()} Traffic Rate Graphs:")
            self.view_window.update_traffic_graphs_auto_cb.setEnabled(True)
            self.view_window.traffic_graphs_frame.setEnabled(True)

            host_mac_addr = self._get_mac_addr_of_selected_traffic_host_item(traffic_host_item)
            self._update_host_traffic_graphs(host_mac_addr)

            if self.view_window.update_traffic_graphs_auto_cb.isChecked():
                self.traffic_graphs_update_timer = QTimer()
                self.traffic_graphs_update_timer.timeout.connect(lambda:
                                                                 self._update_host_traffic_graphs(host_mac_addr))
                self.traffic_graphs_update_timer.start(2 * 1000)  # Updating graphs every 2 sec
        except Exception as e:
            print("ERROR OCCURRED ON TRAFFIC HOST CLICKED:::", e, "TYPE:", type(e))

    @staticmethod
    def _get_mac_addr_of_selected_traffic_host_item(traffic_host_item) -> str:
        """
        Extracts the MAC address of a selected traffic host item.
        :param traffic_host_item: The selected traffic host item.
        :return: The MAC address of the host.
        """
        host_item_text = traffic_host_item.text()
        host_mac_addr: str
        if "-" in host_item_text:
            host_mac_addr = host_item_text.split("-")[0].strip()  # Get the MAC addr part
        else:
            host_mac_addr = host_item_text

        return host_mac_addr

    def _update_host_traffic_graphs(self, host_mac_addr: str) -> None:
        """
        Updates the traffic graphs for a host on the traffic sniffer screen.
        :param host_mac_addr: The host's MAC address
        :return: None
        """
        if self.view_window.stackedWidget.currentIndex() != 2 or \
                not self.view_window.sniffer_hosts_list_widget.currentItem():
            print("STOPPING THE TRAFFIC PLOT UPDATES TIMER")
            # If the screen is no longer looking at the traffic sniffer screen or no host is selcted - stop the updates timer
            if self.traffic_graphs_update_timer and self.traffic_graphs_update_timer.isActive():
                self.traffic_graphs_update_timer.stop()
                self.traffic_graphs_update_timer = None
                return

        sniffer_obj = self.network_module.sniffer
        with sniffer_obj.traffic_graphs_data_lock:
            if host_mac_addr not in sniffer_obj.hosts_datetime_to_packets_amount.keys():
                print("NOT IN:::", sniffer_obj.hosts_datetime_to_packets_amount.keys())
                times, incoming_data, outgoing_data = [], [], []
            else:
                data = sniffer_obj.hosts_datetime_to_packets_amount[host_mac_addr]
                times = data.keys()
                incoming_data = [data[time][0] for time in times]
                outgoing_data = [data[time][1] for time in times]

            self.view_window.load_host_traffic_graphs(times, incoming_data, outgoing_data)

    def _handle_update_traffic_graphs_setting_cb_change(self) -> None:
        """
        Handles the "AAutomatically update graphs" checkbox in the traffic sniffer screen.
        If the setting was disabled, stop the update timer if it's running, else start it.
        :return: None
        """
        if self.view_window.update_traffic_graphs_auto_cb.isChecked():
            # Setting checkbox enabled
            curr_item = self.view_window.sniffer_hosts_list_widget.currentItem()
            if curr_item is not None:
                selected_host_mac_addr = self._get_mac_addr_of_selected_traffic_host_item(curr_item)
                self._update_host_traffic_graphs(selected_host_mac_addr)  # Update the graphs
                # Create the time to keep updating the graphs
                self.traffic_graphs_update_timer = QTimer()
                self.traffic_graphs_update_timer.timeout.connect(lambda:
                                                                 self._update_host_traffic_graphs(
                                                                     selected_host_mac_addr))
                self.traffic_graphs_update_timer.start(2 * 1000)  # Updating graphs every 2 sec
        else:
            # Checkbox setting disabled
            if self.traffic_graphs_update_timer and self.traffic_graphs_update_timer.isActive():
                self.traffic_graphs_update_timer.stop()
                self.traffic_graphs_update_timer = None

    def _handle_new_traffic_host_signal(self, new_traffic_host_mac_addr: str) -> None:
        """
        Handles the new traffic host signal of the network module emitted by the Traffic Sniffer when detected
        traffic from a new host.
        Adds the new host to the list view in the traffic sniffer screen.
        Tries to find the IP and type of the given MAC address host to show in the list widget as well.
        :param new_traffic_host_mac_addr: The new traffic host MAC address
        :return: None
        """
        host_obj = self.network_module.get_host_obj(host_mac_addr=new_traffic_host_mac_addr)
        if host_obj:
            new_traffic_host_ip_addr = host_obj.ip_address
            device_type = host_obj.type
        else:
            new_traffic_host_ip_addr = ""
            device_type = "computer"
        self.view_window.add_host_to_traffic_hosts_list_widget(new_traffic_host_mac_addr, new_traffic_host_ip_addr,
                                                               device_type)

    def _handle_traffic_host_signal(self, host_mac_addr: str) -> None:
        """
        Handles the traffic detected from host signal.
        Sets the traffic icon in the host's widget.
        Adds the event to the app logger.
        :param host_mac_addr: The host MAC address.
        :return: None
        """
        host_widget = self.view_window.find_host_widget_from_topology(host_mac_address=host_mac_addr)
        if host_widget:
            host_widget.set_traffic_icon(is_high_traffic=False)  # TODO - 21/04
            # Add event to logger
            self.view_window.logger.add_event(
                event_message=f"Traffic detected for {host_widget.host_obj.ip_address}",
                event_type=self.view_window.logger.TRAFFIC_EVENT_TYPE)

    def _handle_high_traffic_host_signal(self, host_mac_addr: str) -> None:
        """
        Handles the high traffic detected from host signal.
        Sets the high-traffic icon in the host's widget.
        Adds the event to the app logger.
        :param host_mac_addr: The host MAC address.
        :return: None
        """
        host_widget = self.view_window.find_host_widget_from_topology(host_mac_address=host_mac_addr)
        if host_widget:
            host_widget.set_traffic_icon(is_high_traffic=True)
            # Add event to logger
            self.view_window.logger.add_event(
                event_message=f"High traffic detected for {host_widget.host_obj.ip_address}",
                event_type=self.view_window.logger.HIGH_TRAFFIC_EVENT_TYPE)

    # ------ SAVE SETTINGS HANDLING FUNCTIONS ------
    def _handle_save_settings(self) -> None:
        """
        Saves the current settings to the config.ini file.
        :return: None
        """
        try:
            config = configparser.ConfigParser()

            config.read("config.ini")
            if not config.sections():
                config.add_section("Scanner Settings")
                config.add_section("Fingerprint Settings")

            scanner_settings = config["Scanner Settings"]
            scanner_settings["interval"] = str(self.view_window.interval_setting_spinbox.value())
            scanner_settings["timeout"] = str(self.view_window.timeout_setting_spinbox.value())
            if self.view_window.arp_scan_method_radio_button.isChecked():
                scanner_settings["method"] = "ARP"
            elif self.view_window.icmp_scan_method_radio_button.isChecked():
                scanner_settings["method"] = "ICMP"
            else:
                scanner_settings["method"] = "BOTH"
            scanner_settings["retrieve hostname"] = str(self.view_window.retrieve_hostname_setting_switch.isChecked())
            scanner_settings["retrieve latency"] = str(self.view_window.retrieve_res_time_setting_switch.isChecked())
            scanner_settings["automatically add router"] = str(self.view_window.router_setting_switch.isChecked())

            fingerprint_settings = config["Fingerprint Settings"]
            fingerprint_settings["run well known port scan"] = str(
                self.view_window.well_known_port_scan_fp_setting_switch.isChecked())
            fingerprint_settings["run full port scan"] = str(
                self.view_window.full_port_scan_fp_setting_switch.isChecked())
            fingerprint_settings["run os detection scan"] = str(
                self.view_window.os_detection_fp_setting_switch.isChecked())
            fingerprint_settings["scan udp ports"] = str(self.view_window.scan_udp_ports_setting_switch.isChecked())

            with open("config.ini", "w") as configfile:
                config.write(configfile)
        except Exception as e:
            print("ERROR on handle save settings:::", e)

    def _apply_settings(self, settings: configparser.ConfigParser) -> None:
        """
        Applies the given settings on the app.
        :param settings: The settings ConfigParser object.
        :return: None
        """

        def str_to_bool(value: str) -> bool:
            """
            Function converts true / false written as strings to matching boolean values.
            :param value: The string value
            :return: The boolean value (True / False)
            """
            return value.lower() == "true"

        scanner_settings = settings["Scanner Settings"]
        self.view_window.interval_setting_spinbox.setValue(float(scanner_settings["interval"]))
        self.view_window.timeout_setting_spinbox.setValue(float(scanner_settings["timeout"]))
        if scanner_settings["method"] == "ARP":
            self.view_window.arp_scan_method_radio_button.setChecked(True)
        elif scanner_settings["method"] == "ICMP":
            self.view_window.icmp_scan_method_radio_button.setChecked(True)
        else:
            self.view_window.both_scan_method_radio_button.setChecked(True)
        self.view_window.retrieve_hostname_setting_switch.setChecked(str_to_bool(scanner_settings["retrieve hostname"]))
        self.view_window.retrieve_hostname_setting_switch.animate()
        self.view_window.retrieve_res_time_setting_switch.setChecked(str_to_bool(scanner_settings["retrieve latency"]))
        self.view_window.retrieve_res_time_setting_switch.animate()
        self.view_window.router_setting_switch.setChecked(str_to_bool(scanner_settings["automatically add router"]))
        self.view_window.router_setting_switch.animate()

        fingerprint_settings = settings["Fingerprint Settings"]
        self.view_window.well_known_port_scan_fp_setting_switch.setChecked(
            str_to_bool(fingerprint_settings["run well known port scan"]))
        self.view_window.well_known_port_scan_fp_setting_switch.animate()
        self.view_window.full_port_scan_fp_setting_switch.setChecked(
            str_to_bool(fingerprint_settings["run full port scan"]))
        self.view_window.full_port_scan_fp_setting_switch.animate()
        self.view_window.os_detection_fp_setting_switch.setChecked(
            str_to_bool(fingerprint_settings["run os detection scan"]))
        self.view_window.os_detection_fp_setting_switch.animate()
        self.view_window.scan_udp_ports_setting_switch.setChecked(str_to_bool(fingerprint_settings["scan udp ports"]))
        self.view_window.scan_udp_ports_setting_switch.animate()

    def _handle_exit(self):
        """
        Handles the exit app button.
        Closes all active modules and quits the app.
        :return:
        """
        self.view_window.close()
        self.view_window = None
        self.network_module.hosts_connector.close_connector()
        self.network_module.sniffer.stop_sniffing()
        self.network_module = None
        QCoreApplication.quit()
