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
            bar.setFixedHeight(4)
            bar.setFrameShape(QFrame.Shape.Box)
            bar.setAutoFillBackground(True)
            self.layout.addWidget(bar)
            self.bars.append(bar)

        self.score_label = QLabel()
        self.score_label.setStyleSheet("font-size: 9px; color: gray;")
        self.layout.addWidget(self.score_label)

        self.set_strength(0)

    def set_strength(self, score: int):
        if score == 0:
            color = QColor(211, 47, 47)
            fill_count = 1
            label_text = "Very Weak"
        elif score == 1:
            color = QColor(244, 67, 54)
            fill_count = 2
            label_text = "Weak"
        elif score == 2:
            color = QColor(255, 152, 0)
            fill_count = 3
            label_text = "Fair"
        elif score == 3:
            color = QColor(76, 175, 80)
            fill_count = 4
            label_text = "Strong"
        else:
            color = QColor(46, 125, 50)
            fill_count = 5
            label_text = "Very Strong"

        for i, bar in enumerate(self.bars):
            palette = bar.palette()
            if i < fill_count:
                palette.setColor(QPalette.ColorRole.Window, color)
            else:
                palette.setColor(QPalette.ColorRole.Window, QColor(220, 220, 220))
            bar.setPalette(palette)

        self.score_label.setText(label_text)

    def set_strength_with_feedback(self, score: int, warning: str = "", suggestions: list = None):
        self.set_strength(score)
        if warning:
            self.setToolTip(f"Warning: {warning}")
        elif suggestions:
            self.setToolTip("\n".join(suggestions[:3]))
        else:
            self.setToolTip("")