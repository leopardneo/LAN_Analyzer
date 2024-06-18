"""
Author: Ofir Brovin.
This file is the network module of the LAN Analyzer host connector client.
"""
from __future__ import annotations

import ssl
import sys
import socket
import os.path
import threading

from typing import Tuple

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
        self.__analyzer_address: Tuple[str, int] = analyzer_address
        self.__socket: socket.socket | None = None
        self.__ssl_socket: ssl.SSLSocket | None = None

        self.__buff_size: int = 1024
        self.__downloaded_file: Tuple[str, list] = ("", [])  # Stores the currently in download process file (name, content chunks)

        try:
            self.connect_to_analyzer()
        except (ConnectionError, OSError, socket.timeout) as e:
            print(e)
            sys.exit("Could not connect to the LAN Analyzer.\n"
                     "Please make sure the provided IP and port in the config.ini file are correct,\n"
                     "and that the LAN Analyzer is running and accepting new connections.")
        except ValueError:
            sys.exit("The connection was not allowed by the LAN Analyzer.")

    def connect_to_analyzer(self) -> None:
        """
        Attempts to connect to the LAN Analyzer.
        Starts the _receive_messages thread if the connection was successful.
        (ConnectionError, OSError, socket.timeout) raised if the connection wasn't successful.
        ValueError raised if the connection was refused by the LAN Analyzer.
        :return: None
        """
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__socket.connect(self.__analyzer_address)

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations(cafile=r"src\model\TLS\server_cert.pem")
        context.check_hostname = False  # Allow the script to run on any host (don't check specific hostname)
        self.__ssl_socket = context.wrap_socket(self.__socket)

        request_status = self.__ssl_socket.recv(1024).decode()

        if request_status:
            if request_status == "REFUSED":
                raise ValueError

        # Listen for incoming messages
        receive_thread = threading.Thread(target=self._receive_messages)
        receive_thread.daemon = True
        receive_thread.start()

    def send_message(self, message: str) -> None:
        """
        Sends a message to the LAN Analyzer.
        :param message: The message text.
        :return: None
        """
        try:
            self.__ssl_socket.send(message.encode())
        except OSError:
            # Socket closed
            print("SOCKET CLOSED WHEN TRYING TO SEND A MESSAGE")
            return self._analyzer_disconnected()

    def _receive_messages(self) -> None:
        """
        Receives messages from the LAN Analyzer (runs in a thread).
        :return: None
        """
        while True:
            try:
                data = self.__ssl_socket.recv(self.__buff_size)
            except ConnectionError:
                # Analyzer (server) killed connection
                return self._analyzer_disconnected()
            if not data:
                # Analyzer closed
                return self._analyzer_disconnected()
            else:
                if data.startswith(b"<MESSAGE>"):
                    # Regular message of type - REGULAR / WARNING / CRITICAL
                    data = data[9:]  # Remove <MESSAGE> prefix
                    message_type, message_text = data.split(b"@", maxsplit=1)
                    self.message_received_signal.emit(message_text.decode(), message_type.decode())
                elif data.startswith(b"<FILE_TRANSFER_START>"):
                    # File transfer start declaration message.
                    self.__buff_size = 1024 * 8  # Set buffer size bigger to support file transfer
                    file_name = data.split(b"@", maxsplit=1)[1]  # Extract the file name from the FILE_TRANSFER_START message
                    self.__downloaded_file = (file_name.decode(), [])  # Initialize the downloaded file storing var
                    # Remove the <FILE_TRANSFER_START>@{file_name} prefix and check if there is file data after it
                    data = data[22 + len(file_name):]  # (22 = len of <FILE_TRANSFER_START> header)
                    if data:
                        self.__downloaded_file[1].append(data)
                        # Was the trailing data the entire file?
                        if self.__downloaded_file[1][-1].endswith(b"<FILE_TRANSFER_END>"):
                            self._file_download_completed_handler()
                else:
                    # Data is part of a downloaded file contents.
                    self.__downloaded_file[1].append(data)
                    if self.__downloaded_file[1][-1].endswith(b"<FILE_TRANSFER_END>"):
                        # Downloading the file has completed - received all chunks.
                        self._file_download_completed_handler()

    def _file_download_completed_handler(self) -> None:
        """
        Handles file has finished being received.
        Saves the file to the saved_files dir and restores the buffer size.
        :return: None
        """
        self.__buff_size = 1024
        file_name = self.__downloaded_file[0]
        file_contents = b"".join(self.__downloaded_file[1])  # Combine all the file content chunks
        # Create the saved_files directory if it doesn't exist
        if not os.path.exists(os.getcwd() + r"\saved_files"):
            os.mkdir("saved_files")
        with open(rf"saved_files\{file_name}", "wb") as save_downloaded_file:
            save_downloaded_file.write(file_contents[:-19])  # Remove the <FILE_TRANSFER_END> tail
        self.message_received_signal.emit(f"Saved file \"{file_name}\" in the saved_files folder", "FINISHED_DOWNLOAD")

    def _analyzer_disconnected(self) -> None:
        """
        Updates the module values to indicate that the LAN Analyzer has disconnected.
        :return: None
        """
        self.__ssl_socket.close()
        self.analyzer_disconnected_signal.emit()
