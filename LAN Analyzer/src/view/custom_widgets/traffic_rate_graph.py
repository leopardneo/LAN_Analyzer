"""
Author: Ofir Brovin.
This file contains the traffic rate graph widget of LAN Analyzer application.
"""
import numpy as np

import matplotlib.pyplot as plt
import matplotlib.dates as mdates
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar

from PyQt5 import QtCore
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QVBoxLayout, QWidget


class TrafficRateGraph(QWidget):
    """
    QWidget for displaying a traffic rate matplotlib graph.
    """
    def __init__(self, parent_widget=None):
        """
        Initiates the graph widget.
        :param parent_widget: The parent widget of the graph.
        """
        super().__init__(parent_widget)

        self.data = None
        self.times = None

        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.figure, self.ax = plt.subplots()
        self.canvas = FigureCanvas(self.figure)
        self.toolbar = NavigationToolbar(self.canvas, self)

        # Configure location label on the toolbar
        self.toolbar.locLabel.setAlignment(QtCore.Qt.AlignCenter)
        self.toolbar.locLabel.setFont(QFont("Ariel", 10))

        self.layout.addWidget(self.toolbar)
        self.layout.addWidget(self.canvas)

        self.annot = None  # Stores the annotation object

        # Connect mouse hover event
        self.canvas.mpl_connect("motion_notify_event", self._hover_event)

    def clear_plot(self) -> None:
        """
        Clears the current plot.
        :return: None
        """
        self.ax.clear()
        self.canvas.draw()

    def update_data(self, data, times, color: str) -> None:
        """
        Updates the plot with new data.
        :param data: The traffic rate data.
        :param times: The corresponding timestamps.
        :param color: The color of the plot line.
        :return: None
        """
        self.ax.clear()
        times_no_ms = [time.replace(microsecond=0) for time in times]  # Remove milliseconds
        self.times = mdates.date2num(times_no_ms)  # Convert times to matplotlib date numbers
        self.data = data
        self.ax.plot(times_no_ms, data, '.-', label='Packets Per Second', color=color)
        self.ax.legend()
        self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%d/%m %H:%M:%S'))  # Format x-axis labels
        self.ax.tick_params(axis='x', rotation=45, labelsize=8)  # Rotate x-axis labels for better readability

        self.figure.tight_layout()
        self.canvas.draw()

    def _hover_event(self, event) -> None:
        """
        Handles the hover event over the plot.
        :param event: The mouse hover event.
        :return: None
        """
        if event.inaxes == self.ax:
            x, y = event.xdata, event.ydata
            if x is not None and y is not None:
                # Find the nearest data point
                if self.times is not None and len(self.times) > 0:
                    # Calculate the distance threshold based on the number of points
                    distance_threshold = 0.15 + len(self.times) * 0.01

                    # Find the nearest data point
                    idx = np.abs(self.times - x).argmin()
                    nearest_x, nearest_y = mdates.num2date(self.times[idx]), self.data[idx]

                    # Set the text in the location label in the toolbar
                    self.toolbar.locLabel.setText(f"Time: {nearest_x.strftime('%d/%m/%Y %H:%M:%S')}"
                                                  f' - Packets Per Second: {int(y)}')

                    # Calculate the distance from the mouse cursor to the nearest point
                    distance = np.sqrt((x - self.times[idx]) ** 2 + (y - nearest_y) ** 2)

                    # Show annotation if the distance is below the threshold (mouse is close enough)
                    if distance < distance_threshold:
                        # Adjust annotation position based on mouse cursor position and plot boundaries
                        bbox = self.ax.get_window_extent()
                        canvas_width, canvas_height = bbox.width, bbox.height
                        ax_pos = self.ax.transData.transform((mdates.date2num(nearest_x), nearest_y))
                        ax_x, ax_y = ax_pos[0], ax_pos[1]
                        ax_x_rel = ax_x / canvas_width
                        ax_y_rel = ax_y / canvas_height

                        offset_x = 40 if ax_x_rel < 0.5 else -120
                        offset_y = 40 if ax_y_rel < 0.5 else -80

                        if self.annot:
                            self.annot.remove()
                        self.annot = self.ax.annotate(f'Time: {nearest_x.strftime("%d/%m/%Y %H:%M:%S")}\n'
                                                      f'Packets Per Second: {nearest_y}',
                                                      xy=(nearest_x, nearest_y),
                                                      xytext=(offset_x, offset_y),
                                                      textcoords='offset points',
                                                      bbox=dict(boxstyle="round", fc="w"),
                                                      arrowprops=dict(arrowstyle="->"))
                        self.canvas.draw_idle()
                    elif self.annot:
                        self.annot.remove()
                        self.annot = None
                        self.canvas.draw_idle()
