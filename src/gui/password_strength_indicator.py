from PyQt6.QtWidgets import QWidget, QHBoxLayout, QFrame
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
            bar.setFixedHeight(4)
            bar.setFrameShape(QFrame.Shape.Box)
            bar.setAutoFillBackground(True)
            self.layout.addWidget(bar)
            self.bars.append(bar)

        self.set_strength(0)

    def set_strength(self, score: int):
        if score <= 2:
            color = QColor(255, 80, 80)
            fill_count = 1 if score >= 1 else 0
        elif score <= 4:
            color = QColor(255, 180, 80)
            fill_count = 2
        elif score <= 6:
            color = QColor(255, 235, 80)
            fill_count = 3
        elif score <= 8:
            color = QColor(100, 200, 100)
            fill_count = 4
        else:
            color = QColor(80, 255, 80)
            fill_count = 5

        for i, bar in enumerate(self.bars):
            palette = bar.palette()
            if i < fill_count:
                palette.setColor(QPalette.ColorRole.Window, color)
            else:
                palette.setColor(QPalette.ColorRole.Window, QColor(220, 220, 220))
            bar.setPalette(palette)