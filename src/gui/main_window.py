import tkinter as tk

from src.database.db import init_db
from src.core.config import ConfigManager
from src.core.state_manager import StateManager


def main():
    # Initialize core systems
    init_db()
    config = ConfigManager()
    state = StateManager()

    root = tk.Tk()
    root.title("CryptoSafe Manager")
    root.geometry("800x600")

    status = tk.Label(
        root,
        text="Status: Locked",
        anchor="w"
    )
    status.pack(fill="x", side="bottom")

    label = tk.Label(
        root,
        text="CryptoSafe Manager",
        font=("Arial", 16)
    )
    label.pack(pady=40)

    root.mainloop()


if __name__ == "__main__":
    main()
