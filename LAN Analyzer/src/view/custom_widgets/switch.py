"""
Author: Ofir Brovin.
This file is a custom switch widget created in PyQt5.
"""
from PyQt5.QtWidgets import QAbstractButton
from PyQt5.QtGui import QPainter, QPalette, QLinearGradient, QGradient, QColor
from PyQt5.QtCore import QSize, QPointF, QPropertyAnimation, QEasingCurve, pyqtSlot, Qt, pyqtProperty


class Switch(QAbstractButton):
    """
    The switch widget class
    """
    def __init__(self, parent_widget=None):
        """
        Initiates the switch.
        :param parent_widget: The parent widget of the switch.
        """
        super().__init__(parent_widget)
        self.setCheckable(True)
        self.clicked.connect(self.animate)
        self.position = 0.0
        self.animation = QPropertyAnimation(self, b'position')
        self.animation.setPropertyName(b'position')
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.setDuration(200)
        self.animation.setEasingCurve(QEasingCurve.InOutCirc)
        self.animation.finished.connect(self.update)
        self.setFixedSize(self.sizeHint())

    def sizeHint(self):
        """
        Provides the size for the switch widget.
        :return: QSize object of the size.
        """
        return QSize(47, 23)

    @pyqtProperty(float)
    def position(self) -> float:
        """
        Property to get the current position of the switch.
        :return: The current position of the switch (float).
        """
        return self.mPosition

    @position.setter
    def position(self, value: float) -> None:
        """
        Setter for the position property to update the switch's position.
        :param value: The new position value.
        :return: None
        """
        # print("Position set:", value)  # DEBUG
        self.mPosition = value
        self.update()

    @pyqtSlot(bool, name='animate')
    def animate(self):
        """
        Slot to handle the animation of the switch when it is clicked.
        """
        self.animation.setDirection(QPropertyAnimation.Forward if self.isChecked() else QPropertyAnimation.Backward)
        self.animation.start()  # Start the animation in the appropriate direction

    def paintEvent(self, event) -> None:
        """
        Handles the paint event.
        :param event: The paint event (QAbstractButton).
        :return: None
        """
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        self._draw(painter)

    def _draw(self, painter) -> None:
        """
        Custom drawing method for the switch.
        :param painter: QPainter used for drawing.
        :return: None
        """
        r = self.rect()
        margin = r.height() // 10
        shadow = self.palette().color(QPalette.Dark)
        light = self.palette().color(QPalette.Light)
        painter.setPen(Qt.NoPen)

        # Create gradient for the background
        gradient = QLinearGradient()
        gradient.setSpread(QGradient.PadSpread)

        if self.isChecked():
            gradient.setColorAt(0, shadow.darker(130))
            gradient.setColorAt(0.1, QColor(0, 0, 255).darker(130))  # Blue background when checked
            gradient.setColorAt(0.9, QColor(0, 0, 255).darker(130))
            gradient.setColorAt(1, shadow.darker(130))
        else:
            gradient.setColorAt(0, shadow.darker(130))
            gradient.setColorAt(1, light.darker(130))

        gradient.setStart(0, r.height())
        gradient.setFinalStop(0, 0)
        painter.setBrush(gradient)
        painter.drawRoundedRect(r, r.height() / 2, r.height() / 2)

        gradient.setColorAt(0, shadow.darker(140))
        gradient.setColorAt(1, light.darker(160))
        gradient.setStart(0, 0)
        gradient.setFinalStop(0, r.height())
        painter.setBrush(gradient)
        painter.drawRoundedRect(r.adjusted(margin, margin, -margin, -margin), r.height() / 2, r.height() / 2)

        # Draw the circle (indicator)
        painter.setBrush(Qt.white)  # Set color for the circle
        x = r.height() / 2.0 + self.position * (r.width() - r.height())  # Calculate the x position of the circle
        painter.drawEllipse(QPointF(x, r.height() / 2), r.height() / 2 - margin, r.height() / 2 - margin)

    def resizeEvent(self, event) -> None:
        """
        Handles the resize event.
        Redraws the switch after the resize (update).
        :param event: QResizeEvent event (QAbstractButton).
        :return: None
        """
        self.update()
