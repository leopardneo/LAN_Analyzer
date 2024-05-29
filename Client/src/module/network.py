"""
Author: Ofir Brovin
This file is the network module of the LAN Analyzer host connector client.
"""
from __future__ import annotations

import os.path
import ssl
import sys
import socket
import threading

from typing import Tuple, Literal

from PyQt5.QtCore import pyqtSignal, QObject


class ConnectorClientNetwork(QObject):
    """
    LAN Analyzer host connector client network module.
    """
    message_received_signal: pyqtSignal = pyqtSignal(str, str)  # Carries the new message text, type
    analyzer_disconnected_signal: pyqtSignal = pyqtSignal()

    def __init__(self, analyzer_address: Tuple[str, int]):
        """
        Initiates the connector network module.
        :param analyzer_address: The LAN Analyzer listening address to connect to. [IP, port]
        """
        super().__init__()
        self.analyzer_address: Tuple[str, int] = analyzer_address
        self.socket: socket.socket | None = None
        self.ssl_socket: ssl.SSLSocket | None = None

        self.buff_size: int = 1024
        self.downloaded_file: Tuple[str, list] = ("", [])  # Stores the currently in download process file (name, content chunks)

        try:
            connect_request_status: str = self.connect_to_analyzer()
        except (ConnectionError, OSError, socket.timeout) as e:
            print(e)
            sys.exit("Could not connect to the LAN Analyzer.\n"
                     "Please make sure the provided IP and port in the config.ini file are correct,\n"
                     "and that the LAN Analyzer is running and accepting new connections.")
        if connect_request_status:
            if connect_request_status == "REFUSED":
                sys.exit("The connection was not allowed by the LAN Analyzer.")
        # self.socket.send(f"Server hello username@{self.username}".encode())

        # Listen for incoming messages
        receive_thread = threading.Thread(target=self._receive_messages)
        receive_thread.daemon = True
        receive_thread.start()
        # self.handle_connection()

    def connect_to_analyzer(self) -> Literal["ACCEPTED", "REFUSED"] | None:
        """
        Attempts to connect to the LAN Analyzer.
        ConnectionError raised if connecting failed, request_status ("ACCEPTED" | "REFUSED) returned if connected.
        :return: The connection request status or ConnectionError.
        """
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect(self.analyzer_address)

        # Wrap the socket with SSL
        self.ssl_socket = ssl.wrap_socket(self.socket, cert_reqs=ssl.CERT_NONE)

        request_status = self.ssl_socket.recv(1024).decode()

        # request_status = self.socket.recv(1024).decode()
        return request_status

    def send_message(self, message: str) -> None:
        """
        Sends a message to the LAN Analyzer.
        :param message: The message text.
        :return: None
        """
        try:
            # self.socket.send(message.encode())
            self.ssl_socket.send(message.encode())
        except OSError:
            # Socket closed
            print("SOCKETS CLOSED WHEN TRYING TO SEND A MESSAGE")
            return self.analyzer_disconnected()

    def _receive_messages(self):
        """
        Receives messages from the LAN Analyzer (runs in a thread).
        :return: None
        """
        while True:
            try:
                data = self.ssl_socket.recv(self.buff_size)
            except ConnectionError:
                # Analyzer (server) killed connection
                return self.analyzer_disconnected()
            if not data:
                # Analyzer closed
                return self.analyzer_disconnected()
            else:
                if data.startswith(b"<MESSAGE>"):
                    # Regular message of type - REGULAR / WARNING / CRITICAL
                    data = data[9:]  # Remove <MESSAGE> prefix
                    message_type, message_text = data.split(b"@", maxsplit=1)
                    self.message_received_signal.emit(message_text.decode(), message_type.decode())
                elif data.startswith(b"<FILE_TRANSFER_START>"):
                    # File transfer start declaration message.
                    self.buff_size = 1024 * 8  # Set buffer size bigger to support file transfer
                    file_name = data.split(b"@", maxsplit=1)[1].decode()  # Extract the file name from the FILE_TRANSFER_START message
                    self.downloaded_file = (file_name, [])  # Initialize the downloaded file storing var
                    # Remove the <FILE_TRANSFER_START>@{file_name} prefix and check if there is file data after it
                    data = data[22 + len(file_name):]  # (22 = len of <FILE_TRANSFER_START> header)
                    if data:
                        self.downloaded_file[1].append(data)
                        # Was the trailing data the entire file?
                        if self.downloaded_file[1][-1].endswith(b"<FILE_TRANSFER_END>"):
                            self._file_download_completed_handler()
                else:
                    # Data is part of a downloaded file contents.
                    self.downloaded_file[1].append(data)
                    if self.downloaded_file[1][-1].endswith(b"<FILE_TRANSFER_END>"):
                        # Downloading the file has completed - received all chunks.
                        self._file_download_completed_handler()

    def _file_download_completed_handler(self) -> None:
        """
        Handles file has finished being received.
        Saves the file to the saved_files dir and restores the buffer size.
        :return:
        """
        self.buff_size = 1024
        file_name = self.downloaded_file[0]
        file_contents = b"".join(self.downloaded_file[1])  # Combine all the file content chunks
        # Create the saved_files directory if it doesn't exist
        if not os.path.exists(os.getcwd() + r"\saved_files"):
            os.mkdir("saved_files")
        with open(rf"saved_files\{file_name}", "wb") as save_downloaded_file:
            save_downloaded_file.write(file_contents[:-19])  # Remove the <FILE_TRANSFER_END> tail
        self.message_received_signal.emit(f"Saved file \"{file_name}\" in the saved_files folder", "FINISHED_DOWNLOAD")

    def analyzer_disconnected(self) -> None:
        """
        Updates the module values to indicate that the Analyzer has disconnected.
        :return:
        """
        # self.socket.close()
        self.ssl_socket.close()
        self.analyzer_disconnected_signal.emit()
