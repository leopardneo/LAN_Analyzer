"""
Author: Ofir Brovin.
This file is a custom network diagram representation widget created in PyQt5.
"""
from __future__ import annotations

import math
from typing import List, Dict

from PyQt5.QtWidgets import QGraphicsScene, QGraphicsProxyWidget, QMenu, QGraphicsLineItem

from .host import HostWidget


class Node(QGraphicsProxyWidget):
    """
    Node in the diagram
    """
    def __init__(self, host_widget, x, y):
        """
        Initiates the node
        :param host_widget: The host (custom) widget to set as the node's widget
        :param x: The x coordinate of the node in the diagram.
        :param y: The y coordinate of the node in the diagram.
        """
        super().__init__()
        self.host_widget = host_widget
        self.setWidget(host_widget)
        self.setPos(x, y)
        self.setToolTip(host_widget.host_obj.ip_address)

    def contextMenuEvent(self, event):
        """
        The context menu - right click of the node.
        :param event: The right click event (QGraphicsProxyWidget).
        :return:
        """
        if not self.host_widget.host_obj.ip_address:
            return
        menu = QMenu()
        if self.host_widget.host_obj.flagged:
            flag = False
            action_text = "Remove Flag"
        else:
            flag = True
            action_text = "Flag Host"
        flag_host_action = menu.addAction(action_text)
        action = menu.exec_(event.screenPos())
        if action == flag_host_action:
            self.host_widget.set_flagged(flag)


class Link(QGraphicsLineItem):
    """
    The link that connects two nodes in the diagram.
    """
    def __init__(self, start_node, end_node, new_line: bool):
        """
        Initiates the link (line).
        :param start_node: The link start node.
        :param end_node: The link end node.
        :param new_line: Is the connection happening with a node that is within a new line.
        """
        super().__init__()
        self.start_node = start_node
        self.end_node = end_node
        self._update_position(new_line)

    def _update_position(self, new_line: bool) -> None:
        """
        Sets the position of the link.
        :param new_line: Is the connection happening with a node that is within a new line.
        :return: None
        """
        if new_line:
            self.setLine(self.start_node.x() + self.start_node.widget().width() / 2,
                         self.start_node.y() + self.start_node.widget().height(),
                         self.end_node.x() + self.end_node.widget().width() / 2, self.end_node.y())
        else:
            self.setLine(self.start_node.x() + self.start_node.widget().width(),
                         self.start_node.y() + self.start_node.widget().height() / 2, self.end_node.x(),
                         self.end_node.y() + self.end_node.widget().height() / 2)


class NetworkTopology(QGraphicsScene):
    """
    The network topology (diagram).
    """
    def __init__(self, parent_widget=None):
        """
        Initiates the topology vars.
        :param parent_widget: The parent widget of the topology.
        """
        super().__init__(parent_widget)

        self.nodes: List[Node] = []
        self.links: List[Link] = []
        self.hosts_widgets: List[HostWidget] = []
        self.ip_addr_to_host_widget_dict: Dict[str, HostWidget] = {}  # {IP: HostWidget}
        self.mac_addr_to_host_widget_dict: Dict[str, HostWidget] = {}  # {MAC: HostWidget}
        self.full_topology_widgets: List[HostWidget] = []  # Router is in index 0 in the list and reg hosts come after.
        self.is_full_topology_shown: bool = False

    @staticmethod
    def create_hosts_widgets_list(hosts_objs_list: list) -> List[HostWidget]:
        """
        Creates a list of host widgets of the given Host objects.
        :param hosts_objs_list: The hosts objects list.
        :return: List of the HostWidgets.
        """
        return [HostWidget(host) for host in hosts_objs_list]

    @staticmethod
    def create_copy_hosts_widgets_list(hosts_widgets_list: List[HostWidget]) -> List[HostWidget]:
        """
        Creates a copy of host widgets from a hosts widgets list.
        :param hosts_widgets_list: List containing HostWidgets to copy.
        :return: List with copies of the HostWidgets.
        """
        return [HostWidget(host_widg.host_obj) for host_widg in hosts_widgets_list]

    def create_topology(self, hosts_widgets_list: List[HostWidget], router_host: object | None, is_full_topology: bool):
        """
        Creates the network topology diagram.
        :param hosts_widgets_list: The hosts widgets.
        :param router_host: The router Host object
        :param is_full_topology: Is the created topology the full one (no search filters).
        :return: None
        """
        if is_full_topology:
            self.full_topology_widgets.clear()
            self.is_full_topology_shown = True
        else:
            self.is_full_topology_shown = False

        self.clear()
        self.nodes.clear()
        self.links.clear()
        self.hosts_widgets.clear()
        self.ip_addr_to_host_widget_dict.clear()
        self.mac_addr_to_host_widget_dict.clear()

        if not is_full_topology and (not router_host or not router_host.ip_address):
            router_node = None  # Don't include the router
        else:
            router_host_widget = HostWidget(router_host)
            router_node = self._add_node(router_host_widget, 370, 0)
            self.hosts_widgets.append(router_host_widget)
            self.ip_addr_to_host_widget_dict[router_host.ip_address] = router_host_widget
            self.mac_addr_to_host_widget_dict[router_host.mac_address] = router_host_widget
            if is_full_topology:
                self.full_topology_widgets.append(router_host_widget)

        NUMBER_OF_HOSTS_PER_LINE = 4
        counter = 0
        x = 0
        y = 250
        row_index = 0
        hosts_nodes_list: list = [[] for _ in range(0, math.ceil(len(hosts_widgets_list) / NUMBER_OF_HOSTS_PER_LINE))]
        # print("TEST LST:", hosts_nodes_list)
        for host_widget in hosts_widgets_list:
            if counter == NUMBER_OF_HOSTS_PER_LINE:
                # Going one line under
                x = 0
                y += 300
                counter = 0
                row_index += 1

            host_node = self._add_node(host_widget, x, y)
            self.hosts_widgets.append(host_widget)
            self.ip_addr_to_host_widget_dict[host_widget.host_obj.ip_address] = host_widget
            self.mac_addr_to_host_widget_dict[host_widget.host_obj.mac_address] = host_widget

            if is_full_topology:
                self.full_topology_widgets.append(host_widget)

            hosts_nodes_list[row_index].append(host_node)

            x += 250
            counter += 1

        # print("THIS IS A TEST PRINT FOR THE MATRIX:", hosts_nodes_list)

        for index, line in enumerate(hosts_nodes_list):
            if index > 0:
                # Connect between lines
                self._add_link(hosts_nodes_list[index - 1][0], line[0], True)
            if index == 0:
                # Connect the first host in the first line to the router
                if router_node:
                    self._add_link(router_node, line[0], True)
            for i in range(len(line) - 1, 0, -1):
                if index == 0:
                    # Connect the first line to the router
                    if router_node:
                        self._add_link(router_node, line[i], True)
                self._add_link(line[i - 1], line[i], False)
                if index > 0:
                    self._add_link(hosts_nodes_list[index - 1][i], line[i], True)

    def _add_node(self, host_widget, x, y) -> Node:
        """
        Adds a Node to the diagram.
        :param host_widget: The HostWidget for the node.
        :param x: The x coordinate of the node in the diagram.
        :param y: The y coordinate of the node in the diagram.
        :return: The created Node object.
        """
        node = Node(host_widget, x, y)
        self.addItem(node)
        self.nodes.append(node)
        return node

    def _add_link(self, start_node, end_node, new_line) -> None:
        """
        Adds a link (line) to the diagram.
        :param start_node: The link start node.
        :param end_node: The link end node.
        :param new_line: Is the connection happening with a node that is within a new line.
        """
        link = Link(start_node, end_node, new_line)
        self.addItem(link)
        self.links.append(link)
