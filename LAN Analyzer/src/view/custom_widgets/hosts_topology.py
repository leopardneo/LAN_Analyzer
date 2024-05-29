"""
Author: Ofir Brovin
File is a custom network diagram representation widget created in PyQt5.
"""
from __future__ import annotations

import math

from PyQt5.QtWidgets import QGraphicsScene, QGraphicsProxyWidget, QMenu, QGraphicsLineItem, QMainWindow

from typing import List, Dict

from .host import HostWidget
# from LAN_Analyzer_Cache.view.custom_widgets.host import HostWidget


class Node(QGraphicsProxyWidget):
    def __init__(self, host_widget, x, y):
        super(Node, self).__init__()
        self.host_widget = host_widget
        self.setWidget(host_widget)
        self.setPos(x, y)
        self.setToolTip(host_widget.host_obj.ip_address)

    def contextMenuEvent(self, event):
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
        # TODO: discord 11/05 - 20:48


class Link(QGraphicsLineItem):
    def __init__(self, start_node, end_node, new_line: bool):
        super(Link, self).__init__()
        self.start_node = start_node
        self.end_node = end_node
        self.update_position(new_line)

    def update_position(self, new_line: bool):
        # print(self.start_node.x(), ",", self.start_node.y())
        # print(self.end_node.x(), ",", self.end_node.y())
        # print("TESTING:::", self.start_node.widget().height(), "SIZE:", self.start_node.size())
        if new_line:
            self.setLine(self.start_node.x() + self.start_node.widget().width() / 2,
                         self.start_node.y() + self.start_node.widget().height(),
                         self.end_node.x() + self.end_node.widget().width() / 2, self.end_node.y())
        else:
            self.setLine(self.start_node.x() + self.start_node.widget().width(),
                         self.start_node.y() + self.start_node.widget().height() / 2, self.end_node.x(),
                         self.end_node.y() + self.end_node.widget().height() / 2)


class NetworkTopology(QGraphicsScene):
    def __init__(self, parent_window: QMainWindow):
        super(NetworkTopology, self).__init__()

        self.parent_window = parent_window

        self.nodes: List[Node] = []
        self.links: List[Link] = []
        self.hosts_widgets: List[HostWidget] = []
        self.ip_addr_to_host_widget_dict: Dict[str, HostWidget] = {}  # {IP: HostWidget}
        self.mac_addr_to_host_widget_dict: Dict[str, HostWidget] = {}  # {MAC: HostWidget}
        self.full_topology_widgets: List[HostWidget] = []  # Router is in index 0 in the list and reg hosts come after.
        self.is_full_topology_shown: bool = False

    def create_hosts_widgets_list(self, hosts_objs_list: list):
        return [HostWidget(host) for host in hosts_objs_list]

    def create_copy_hosts_widgets_list(self, hosts_widgets_list: List[HostWidget]):
        new_hosts_widgets_list: List[HostWidget] = []
        for host_widg in hosts_widgets_list:
            host = host_widg.host_obj
            print(host_widg.host_obj.ip_address, "FLAGGED IS:::", host.flagged)
            new_host_widget = HostWidget(host)
            new_hosts_widgets_list.append(new_host_widget)
        return new_hosts_widgets_list

    def create_topology(self, hosts_widgets_list: List[HostWidget], router_host: object | None, is_full_topology: bool):
        print("create_topology:")
        print("WIDGETS LIST:", hosts_widgets_list)
        print("ROUTER HOST:", router_host)
        print("IS FULL TOP:", is_full_topology)
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
            router_node = self.add_node(router_host_widget, 370, 0)
            self.hosts_widgets.append(router_host_widget)
            self.ip_addr_to_host_widget_dict[router_host.ip_address] = router_host_widget
            self.mac_addr_to_host_widget_dict[router_host.mac_address] = router_host_widget
            if is_full_topology:
                self.full_topology_widgets.append(router_host_widget)
                # print("APPENDED THE ROUTER:", router_host_widget.host_obj)

        NUMBER_OF_HOSTS_PER_LINE = 4
        print("IM IN")
        counter = 0
        x = 0
        y = 250
        row_index = 0
        hosts_nodes_list: list = [[] for _ in range(0, math.ceil(len(hosts_widgets_list) / NUMBER_OF_HOSTS_PER_LINE))]
        print("TEST LST:", hosts_nodes_list)
        for host_widget in hosts_widgets_list:
            if counter == NUMBER_OF_HOSTS_PER_LINE:
                # Going one line under
                x = 0
                y += 300
                counter = 0
                row_index += 1

            #host_widget = HostWidget(host, host.type)
            host_node = self.add_node(host_widget, x, y)
            self.hosts_widgets.append(host_widget)
            self.ip_addr_to_host_widget_dict[host_widget.host_obj.ip_address] = host_widget
            self.mac_addr_to_host_widget_dict[host_widget.host_obj.mac_address] = host_widget

            if is_full_topology:
                self.full_topology_widgets.append(host_widget)
            try:
                hosts_nodes_list[row_index].append(host_node)
            except Exception as er:
                print("ER (3rd):", er)

            x += 250
            counter += 1

        print("THIS IS A TEST PRINT FOR THE MATRIX:", hosts_nodes_list)

        for index, line in enumerate(hosts_nodes_list):
            if index > 0:
                # Connect between lines
                self.add_link(hosts_nodes_list[index - 1][0], line[0], True)
            if index == 0:
                # Connect the first host in the first line to the router
                if router_node:
                    self.add_link(router_node, line[0], True)
            for i in range(len(line) - 1, 0, -1):
                if index == 0:
                    # Connect the first line to the router
                    if router_node:
                        self.add_link(router_node, line[i], True)
                try:
                    self.add_link(line[i - 1], line[i], False)
                except Exception as e:
                    print("1st ERR", e)
                if index > 0:
                    print("INDEX IS GREATER THEN 0!")
                    try:
                        self.add_link(hosts_nodes_list[index - 1][i], line[i], True)
                    except Exception as ee:
                        print("2nd ERR", ee)

        # self.parent_window.update()

    def add_node(self, host_widget, x, y):
        node = Node(host_widget, x, y)
        self.addItem(node)
        self.nodes.append(node)
        return node

    def add_link(self, start_node, end_node, new_line):
        link = Link(start_node, end_node, new_line)
        self.addItem(link)
        self.links.append(link)
        # return link
