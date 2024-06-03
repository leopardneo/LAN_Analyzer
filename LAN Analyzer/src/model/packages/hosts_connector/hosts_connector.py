"""
Author: Ofir Brovin.
This file contains the Hosts Connector module of the LAN Analyzer application.
"""
from __future__ import annotations

import ssl
import sys
import time
import select
import sqlite3
import threading

from socket import socket, AF_INET, SOCK_STREAM

from typing import List, Tuple, Literal, BinaryIO

from PyQt5.QtCore import pyqtSignal


class AnalyzerHostsConnector:
    """
    LAN Analyzer Hosts Connector module
    """
    def __init__(self, new_host_connected_signal: pyqtSignal, new_message_signal: pyqtSignal,
                 host_disconnected_signal: pyqtSignal, alert_pop_window_signal: pyqtSignal):
        """
        Initiates the Hosts Connector module.
        :param new_host_connected_signal: The signal to emit when a new host has connected.
        :param new_message_signal:  The signal to emit when there is a new message.
        :param host_disconnected_signal: The signal to emit when a host has disconnected.
        :param alert_pop_window_signal: The signal to emit when need to send alert (about port not available).
        """
        self.local_ip_addr = ""  # updated by the network module after a scan
        self.__host_connections_listening_sock: socket | None = None
        self.__state_vars_lock: threading.Lock = threading.Lock()
        self.socket_open: bool = False
        self.__allow_new_connections: bool = False
        self.listening_sock_addr: Tuple[str, int] | None = None

        self.__readsocks: list = []
        self.__writesocks: list = []
        self.__readables: list = []
        self.__writeables: list = []

        self.__new_host_connected_signal: pyqtSignal = new_host_connected_signal
        self.__new_message_signal: pyqtSignal = new_message_signal
        self.__host_disconnected_signal: pyqtSignal = host_disconnected_signal
        self.__alert_pop_window_signal = alert_pop_window_signal

        # SSL context
        self.__context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            self.__context.load_cert_chain(certfile=r'src\model\packages\hosts_connector\data\TLS\server_cert.pem',
                                           keyfile=r'src\model\packages\hosts_connector\data\TLS\server_key.pem')
        except FileNotFoundError:
            sys.exit("Could not find the required TLS files for the hosts connector.\n"
                     "Please make sure you have the TLS required files in the \'src\model\packages\hosts_connector\data\TLS\' folder.\n"
                     "You can create your own certificate if it doesnt exists in the TLS directory.")

    def init_connector(self) -> None:
        """
        Initiates the Hosts Connector sql DB and the listening socket.
        Creates the handle_connections_sockets thread to start handling connections.
        :return: None
        """
        # SQL set-up
        self._create_table()
        # Socket set-up
        self.__host_connections_listening_sock: socket = self._create_connections_socket()
        self.socket_open = True
        self.__allow_new_connections = True
        self.listening_sock_addr = self.__host_connections_listening_sock.getsockname()
        thread = threading.Thread(target=self._handle_connections_sockets)
        thread.daemon = True
        thread.start()

    def close_connector(self) -> None:
        """
        Closes the Hosts Connector module.
        :return: None
        """
        with self.__state_vars_lock:
            self.socket_open = False
        try:
            self.__host_connections_listening_sock.close()
        except:
            pass  # The Socket is not open

    def set_allow_new_connections(self, new_state: bool) -> None:
        """
        Changes the "allow new connections" state to the given state (True / False)
        :param new_state: The new state to set.
        :return: None
        """
        with self.__state_vars_lock:
            self.__allow_new_connections = new_state

    def _create_connections_socket(self) -> socket:
        """
        Creates the listening connections socket.
        Emits the alert signal if port 60000 is not free to use.
        :return:
        """
        ADDR = (self.local_ip_addr, 60000)
        if not self._is_port_free(ADDR):
            new_port = self._get_free_port()
            ADDR = (self.local_ip_addr, new_port)
            self.__alert_pop_window_signal.emit("WARNING", "NOTE: Port 60000 is not available to use.\n"
                                                         f"Using port {new_port} for the Hosts Connector instead.")
        listening_sock = socket(AF_INET, SOCK_STREAM)
        listening_sock.bind(ADDR)
        listening_sock.listen(5)
        return listening_sock

    def _handle_connections_sockets(self) -> None:
        """
        Handles and manages the connections socket. (Runs in a thread)
        :return: None
        """
        # Initialize data
        listening_sock = self.__host_connections_listening_sock
        self.__readsocks = [listening_sock]
        self.__writesocks = []
        print("Hosts Connector socket started.\nWaiting for connections . . .")
        print("CONNECTIONS ADDR:", listening_sock.getsockname())
        while True:
            time.sleep(0.01)
            with self.__state_vars_lock:
                if not self.socket_open:
                    break
            # Loop for data
            self.__readables, self.__writeables, _ = select.select(self.__readsocks, self.__writesocks, [])
            for sockobj in self.__readables:
                if sockobj is listening_sock:
                    try:
                        newsock, address = sockobj.accept()
                        new_ssl_sock = self.__context.wrap_socket(newsock, server_side=True)
                        with self.__state_vars_lock:
                            if not self.__allow_new_connections:
                                new_ssl_sock.send("REFUSED".encode())
                                new_ssl_sock.close()
                                continue
                            else:
                                new_ssl_sock.send("ACCEPTED".encode())
                    except OSError:
                        continue  # The socket was closed
                    print(f"Connection from {address}")
                    self.__readsocks.append(new_ssl_sock)
                    self.__writesocks.append(new_ssl_sock)
                    self.__new_host_connected_signal.emit(address)  # Sends the (IP, port) of the new connected host
                else:
                    try:
                        data = sockobj.recv(1024).decode()  # Client data
                    except ConnectionResetError:
                        # Client killed connection
                        self.__writeables.remove(sockobj)
                        self.disconnect_user(sockobj)
                        continue
                    if not data:
                        self.__writeables.remove(sockobj)
                        self.disconnect_user(sockobj)
                    else:
                        print(f"DATA RECEIVED FROM: {sockobj.getpeername()}", "DATA:", data)
                        addr = sockobj.getpeername()
                        message = str(addr), True, data
                        self._insert_message(host_addr=message[0], is_from_host=message[1], message=message[2],
                                             message_type="REGULAR")
                        self.__new_message_signal.emit(addr)
                        continue

    def disconnect_user(self, user_socket) -> None:
        """
        Disconnects a user from the Hosts Connector, removing him from all relevant data structures.
        arg: The user socket to remove.
        :return: None
        """

        self.__readsocks.remove(user_socket)
        self.__writesocks.remove(user_socket)
        try:
            self.__writeables.remove(user_socket)
        except ValueError:
            pass

        peer_name = user_socket.getpeername()
        user_socket.close()
        self.__host_disconnected_signal.emit(peer_name)

    def get_user_socket_by_addr(self, addr: Tuple[str, int]) -> socket | None:
        """
        Returns the socket that is connected to the given address.
        :param addr: The address to get the socket for.
        :return: The socket for the given address, None if not found.
        """
        for sockobj in self.__writesocks:
            if sockobj.getpeername() == addr:
                return sockobj

    def send_message(self, message_text: str, message_type: Literal["REGULAR", "WARNING", "CRITICAL"],
                     dest_addr: Tuple[str, int]) -> None:
        """
        Sends a message to a connected host.
        :param message_text: The message text.
        :param message_type: The message type ("REGULAR" / "WARNING" / "CRITICAL").
        :param dest_addr: The connected host destination (socket) address.
        :return: None
        """
        dest_user_sock = self.get_user_socket_by_addr(dest_addr)
        if not dest_user_sock:
            # Host has disconnected
            return self.__host_disconnected_signal.emit(dest_addr)
        print("SENDING:", message_text, "TO:", dest_addr)
        dest_user_sock.send(b"<MESSAGE>" + message_type.encode() + b"@" + message_text.encode())
        self._insert_message(host_addr=str(dest_addr), is_from_host=False, message=message_text, message_type=message_type)
        self.__new_message_signal.emit(dest_addr)

    def send_file(self, file: BinaryIO, file_name: str, dest_addr: Tuple[str, int]) -> None:
        """
        Sends a file to a connected host.
        :param file: The file in "rb" open mode.
        :param file_name: The file name.
        :param dest_addr: The connected host destination (socket) address (IP, port).
        :return: None
        """
        dest_user_sock = self.get_user_socket_by_addr(dest_addr)
        if not dest_user_sock:
            # Host has disconnected
            return self.__host_disconnected_signal.emit(dest_addr)
        print("SENDING FILE:", file, "TO:", dest_addr)
        dest_user_sock.send(f"<FILE_TRANSFER_START>@{file_name}".encode())  # Send file transfer start declaration message
        dest_user_sock.sendfile(file)
        dest_user_sock.send(b"<FILE_TRANSFER_END>")  # File transfer finished declaration message
        self._insert_message(host_addr=str(dest_addr), is_from_host=False, message=f"Sent {file_name}", message_type="FILE_SENT")
        self.__new_message_signal.emit(dest_addr)

    # SQL FUNCTIONS
    @staticmethod
    def _create_table() -> None:
        """
        Creates a SQL database file if it doesn't already exist and clears it.
        :return: None
        """
        conn = sqlite3.connect(r"src/model/packages/hosts_connector/data/chat_history.db")

        cursor = conn.cursor()

        cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            host_addr TEXT NOT NULL,
            is_host BOOLEAN NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            message TEXT NOT NULL,
            message_type TEXT NOT NULL
        )
        ''')
        cursor.execute('DELETE FROM messages')  # Clear db

        conn.commit()
        conn.close()

    @staticmethod
    def _insert_message(host_addr: str, is_from_host: bool, message: str,
                        message_type: Literal["REGULAR", "WARNING", "CRITICAL", "FILE_SENT"]) -> None:
        """
        Inserts a message to the SQL DB.
        :param host_addr: The message host addr.
        :param is_from_host: Is from host (client).
        :param message: The message text.
        :param message_type: The message type.
        :return: None
        """
        conn = sqlite3.connect(r"src/model/packages/hosts_connector/data/chat_history.db")
        cursor = conn.cursor()
        cursor.execute('INSERT INTO messages (host_addr, is_host, message, message_type) VALUES (?, ?, ?, ?)',
                       (host_addr, is_from_host, message, message_type))
        conn.commit()
        conn.close()

    @staticmethod
    def get_chat_history(host_addr_tuple: Tuple[str, int]) -> List[Tuple[str, int, str, str]]:
        """
        Gets the chat history of a given connected host addr.
        :param host_addr_tuple: The connected host addr (IP, port)
        :return: List of the messages [timestamp, is_host, message, message_type]
        """
        conn = sqlite3.connect(r"src/model/packages/hosts_connector/data/chat_history.db")
        cursor = conn.cursor()
        cursor.execute('SELECT timestamp, is_host, message, message_type FROM messages WHERE host_addr=? ORDER BY timestamp',
                       (str(host_addr_tuple),))
        history = cursor.fetchall()
        conn.close()
        print("CHAT HISTORY:", history)
        return history

    @staticmethod
    def clear_host_chat(host_addr: Tuple[str, int]) -> None:
        """
        Removes a given connected host addr chat history from the DB.
        :param host_addr: The connected host addr (IP, port)
        :return: None
        """
        conn = sqlite3.connect(r"src/model/packages/hosts_connector/data/chat_history.db")
        cursor = conn.cursor()
        cursor.execute('DELETE FROM messages WHERE host_addr=?', (str(host_addr),))
        conn.commit()
        conn.close()

    @staticmethod
    def _is_port_free(addr: Tuple[str, int]) -> bool:
        """
        Checks if a port is free.
        :param addr: Address with the port (IP, the port)
        :return: True if the port is free, False otherwise
        """
        try:
            with socket(AF_INET, SOCK_STREAM) as s:
                s.bind((addr[0], addr[1]))
        except OSError:
            return False
        return True

    @staticmethod
    def _get_free_port() -> int:
        """
        Retrieves a free - available to use port.
        :return: The port.
        """
        s = socket(AF_INET, SOCK_STREAM)
        s.bind(("", 0))
        s.listen(1)
        port = s.getsockname()[1]
        s.close()
        return port
