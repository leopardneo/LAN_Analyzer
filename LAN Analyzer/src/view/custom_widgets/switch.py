from PyQt5.QtWidgets import QAbstractButton
from PyQt5.QtGui import QPainter, QPalette, QLinearGradient, QGradient, QColor
from PyQt5.QtCore import QSize, QPointF, QPropertyAnimation, QEasingCurve, pyqtSlot, Qt, pyqtProperty


class Switch(QAbstractButton):
    def __init__(self, parent_widget=None):
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
        return QSize(47, 23)

    @pyqtProperty(float)
    def position(self):
        return self.mPosition

    @position.setter
    def position(self, value):
        # print("Position set:", value)  # DEBUG
        self.mPosition = value
        self.update()

    @pyqtSlot(bool, name='animate')
    def animate(self):
        # print("Switch clicked:")  # DEBUG
        # print("Animation state before start:", self.animation.state())
        self.animation.setDirection(QPropertyAnimation.Forward if self.isChecked() else QPropertyAnimation.Backward)
        self.animation.start()
        # print("Animation state after start:", self.animation.state())

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        self.draw(painter)

    def BpaintEvent(self, event):
        painter = QPainter()
        painter.begin(self)
        painter.setRenderHint(QPainter.HighQualityAntialiasing)
        painter.setPen(Qt.NoPen)
        if not self.isChecked():
            painter.setBrush(QColor("#777777"))
            painter.drawRoundedRect(0, 0, self.width(), self.height(), self.height() / 2, self.height() / 2)
        elif self.isChecked():
            painter.setBrush(QColor("#aa00ff"))
            painter.drawRoundedRect(0, 0, self.width(), self.height(), self.height() / 2, self.height() / 2)

    def draw(self, painter):
        r = self.rect()
        margin = r.height() // 10
        shadow = self.palette().color(QPalette.Dark)
        light = self.palette().color(QPalette.Light)
        button = self.palette().color(QPalette.Button)
        painter.setPen(Qt.NoPen)

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
        x = r.height() / 2.0 + self.position * (r.width() - r.height())
        painter.drawEllipse(QPointF(x, r.height() / 2), r.height() / 2 - margin, r.height() / 2 - margin)

    def Adraw(self, painter):
        r = self.rect()
        margin = r.height() // 10
        shadow = self.palette().color(QPalette.Dark)
        light = self.palette().color(QPalette.Light)
        button = self.palette().color(QPalette.Button)
        painter.setPen(Qt.NoPen)

        gradient = QLinearGradient()
        gradient.setSpread(QGradient.PadSpread)

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

        gradient.setColorAt(0, button.darker(130))
        gradient.setColorAt(1, button)

        painter.setBrush(gradient)

        x = r.height() / 2.0 + self.position * (r.width() - r.height())
        painter.drawEllipse(QPointF(x, r.height() / 2), r.height() / 2 - margin, r.height() / 2 - margin)

    def resizeEvent(self, event):
        self.update()
