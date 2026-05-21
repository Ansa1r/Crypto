from PyQt6.QtWidgets import QWidget, QHBoxLayout, QFrame, QLabel
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QPalette, QColor


class PasswordStrengthIndicator(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(2)

        self.bars = []
        for i in range(5):
            bar = QFrame()
            bar.setFixedHeight(6)
            bar.setFrameShape(QFrame.Shape.Box)
            bar.setAutoFillBackground(True)
            self.layout.addWidget(bar)
            self.bars.append(bar)

        self.set_strength(0)

    def set_strength(self, score: int):
        if score == 0:
            color = QColor(211, 47, 47)
            fill_count = 1
        elif score == 1:
            color = QColor(244, 67, 54)
            fill_count = 2
        elif score == 2:
            color = QColor(255, 152, 0)
            fill_count = 3
        elif score == 3:
            color = QColor(76, 175, 80)
            fill_count = 4
        else:
            color = QColor(46, 125, 50)
            fill_count = 5

        for i, bar in enumerate(self.bars):
            palette = bar.palette()
            if i < fill_count:
                palette.setColor(QPalette.ColorRole.Window, color)
            else:
                palette.setColor(QPalette.ColorRole.Window, QColor(220, 220, 220))
            bar.setPalette(palette)