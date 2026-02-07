import tkinter as tk


def main():
    root = tk.Tk()
    root.title("CryptoSafe Manager")
    root.geometry("800x600")

    label = tk.Label(root, text="CryptoSafe Manager — Sprint 1")
    label.pack(pady=20)

    root.mainloop()


if __name__ == "__main__":
    main()
