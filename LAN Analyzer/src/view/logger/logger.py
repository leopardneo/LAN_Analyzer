from PyQt5.QtGui import QIcon, QColor
from PyQt5.QtWidgets import QListWidget, QListWidgetItem

from .event import Event


class Logger:
    SCAN_STARTED_EVENT_TYPE = "SCAN STARTED"
    MID_SCAN_RESULT_EVENT_TYPE = "SCAN HOST RESULT"
    SCAN_FINISHED_EVENT_TYPE = "SCAN FINISHED"
    FP_SCAN_EVENT_TYPE = "FP SCAN"
    TRAFFIC_EVENT_TYPE = "TRAFFIC"
    HIGH_TRAFFIC_EVENT_TYPE = "HIGH TRAFFIC"
    CONNECTED_HOST_CONNECTED_EVENT_TYPE = "NEW CONNECTED HOST"
    CONNECTED_HOST_NEW_MESSAGE_EVENT_TYPE = "CONNECTED HOST NEW MESSAGE"
    CONNECTED_HOST_DISCONNECTED_EVENT_TYPE = "CONNECTED HOST DISCONNECTED"

    def __init__(self, log_list_widget: QListWidget):
        self.events = []
        self.log_list_widget = log_list_widget

    def add_event(self, event_message: str, event_type: str) -> None:
        """
        Creates an Event object for the given event details and adds it to the logger
        :param event_message: The event message to show in the logger screen
        :param event_type: The event type (scan related, fp scan, connected host...)
        :return: None
        """
        new_event = Event(event_message=event_message, event_type=event_type)
        self.events.append(new_event)
        # Add new event to the list widget
        event_item = QListWidgetItem()
        if event_type == self.SCAN_STARTED_EVENT_TYPE:
            event_item.setBackground(QColor("#ADD8E6"))
            icon = QIcon(r"src/view/icons/start_scan_icon.png")
        elif event_type == self.MID_SCAN_RESULT_EVENT_TYPE:
            event_item.setBackground(QColor("#DCEAEF"))
            icon = QIcon(r"src/view/icons/ip-address.png")
        elif event_type == self.SCAN_FINISHED_EVENT_TYPE:
            event_item.setBackground(QColor("#77DEFF"))
            icon = QIcon(r"src/view/icons/checkmark.png")
        elif event_type == self.FP_SCAN_EVENT_TYPE:
            event_item.setBackground(QColor("#CFE6FF"))
            icon = QIcon(r"src/view/icons/fingerprint_scan.png")
        elif event_type == self.TRAFFIC_EVENT_TYPE:
            event_item.setBackground(QColor("#FFE5A1"))
            icon = QIcon(r"src/view/icons/traffic.png")
        elif event_type == self.HIGH_TRAFFIC_EVENT_TYPE:
            event_item.setBackground(QColor("#FFCC80"))
            icon = QIcon(r"src/view/icons/high_traffic.png")
        elif event_type == self.CONNECTED_HOST_CONNECTED_EVENT_TYPE:
            event_item.setBackground(QColor("#6FA5FF"))
            icon = QIcon(r"src/view/icons/connected.png")
        elif event_type == self.CONNECTED_HOST_NEW_MESSAGE_EVENT_TYPE:
            event_item.setBackground(QColor("#92B3E8"))
            icon = QIcon(r"src/view/icons/message_received.png")
        elif event_type == self.CONNECTED_HOST_DISCONNECTED_EVENT_TYPE:
            event_item.setBackground(QColor("#6FA5FF"))
            icon = QIcon(r"src/view/icons/disconnected.png")

        event_item.setText(event_message)
        event_item.setIcon(icon)
        self.log_list_widget.addItem(event_item)
        self.log_list_widget.scrollToItem(event_item)

    def get_event_at_index(self, index: int) -> Event:
        """
        Returns the saved event in the given index.
        :param index: The index
        :return: The Event
        """
        return self.events[index]
