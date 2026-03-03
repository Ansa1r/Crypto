import pytest
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt
import sys

@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication(sys.argv)
    yield app

def test_main_window_launches(qapp):
    from src.gui.main_window import CryptoSafeMainWindow
    window = CryptoSafeMainWindow()
    window.show()
    assert window.isVisible()
    window.close()

def test_unlock_dialog(qapp):
    from src.gui.main_window import UnlockDialog
    dialog = UnlockDialog()
    assert dialog.windowTitle() == "Unlock Vault"
    dialog.close()

def test_first_run_dialog(qapp):
    from src.gui.main_window import FirstRunDialog
    dialog = FirstRunDialog()
    assert "First Run" in dialog.windowTitle()
    dialog.close()