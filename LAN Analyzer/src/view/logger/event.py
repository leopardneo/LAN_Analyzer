"""
Author: Ofir Brovin
This is the Event class representing an event in the LAN Analyzer logger.
"""
import datetime


class Event:
    """
    Event representation class (log event)
    """
    def __init__(self, event_message: str, event_type: str):
        """
        Initiates the event object.
        :param event_message: The event message.
        :param event_type: The event type.
        """
        self.event_message: str = event_message
        self.event_type: str = event_type
        self.event_timestamp: str = datetime.datetime.now().strftime("%d/%m/%y - %H:%M:%S")
