import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import os
import sys
import secrets

try:
    from src.core.state_manager import StateManager
    from src.core.events import EventBus
except ImportError:
    class StateManager:
        def __init__(self):
            self.is_locked = True
            self.current_user = None
    class EventBus:
        def publish(self, event_name, data=None):
            print(f"[EVENT] {event_name} {data or ''}")
state_manager = StateManager()
event_bus = EventBus()

class CryptoSafeMainWindow:
    def __init__(self, root):
        self.root = root
        self.root.title("CryptoSafe Manager")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)

        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure("TButton", padding=8, font=("Helvetica", 10))
        self.style.configure("TLabel", font=("Helvetica", 11))
        self.style.map("TButton",
                       background=[("active", "#4a90e2")],
                       foreground=[("active", "white")])

        self._create_menu()
        self._create_main_content()
        self._create_status_bar()
        self._check_lock_state()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    def _create_menu(self):
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Vault...", command=self.new_vault)
        file_menu.add_command(label="Open Vault...", command=self.open_vault)
        file_menu.add_separator()
        file_menu.add_command(label="Backup...", command=self.backup)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_closing)
        menubar.add_cascade(label="File", menu=file_menu)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Add Entry...", command=self.add_entry)
        edit_menu.add_command(label="Edit Selected", command=self.edit_entry)
        edit_menu.add_command(label="Delete Selected", command=self.delete_entry)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Show Audit Log", command=self.show_audit_log)
        view_menu.add_command(label="Settings...", command=self.show_settings)
        menubar.add_cascade(label="View", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def _create_main_content(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        if state_manager.is_locked:
            self.lock_frame = ttk.Frame(main_frame)
            self.lock_frame.pack(fill=tk.BOTH, expand=True)

            ttk.Label(
                self.lock_frame,
                text="CryptoSafe is Locked",
                font=("Helvetica", 24, "bold")
            ).pack(pady=80)

            ttk.Label(
                self.lock_frame,
                text="Please enter your master password to unlock the vault.",
                font=("Helvetica", 12)
            ).pack(pady=10)

            ttk.Button(
                self.lock_frame,
                text="Unlock Vault",
                command=self.unlock_dialog
            ).pack(pady=20)
        else:
            columns = ("title", "username", "url", "updated")
            self.tree = ttk.Treeview(main_frame, columns=columns, show="headings")
            self.tree.heading("title", text="Title")
            self.tree.heading("username", text="Username")
            self.tree.heading("url", text="URL")
            self.tree.heading("updated", text="Last Updated")
            self.tree.column("title", width=220, anchor="w")
            self.tree.column("username", width=180)
            self.tree.column("url", width=280)
            self.tree.column("updated", width=140)
            self.tree.pack(fill=tk.BOTH, expand=True)
            self._fill_test_data()

    def _fill_test_data(self):
        test_data = [
            ("Google", "max123@gmail.com", "https://accounts.google.com", "2025-02-10"),
            ("GitHub", "Ansa1r", "https://github.com/login", "2025-01-28"),
            ("Bank", "user456", "https://online.bank.ru", "2024-12-15"),
        ]
        for item in test_data:
            self.tree.insert("", tk.END, values=item)

    def _create_status_bar(self):
        self.status_var = tk.StringVar()
        self.status_var.set("Locked | No user session")

        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=(10, 4)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def _check_lock_state(self):
        db_path = "cryptosafe.db"  # можно позже взять из config
        if not os.path.exists(db_path):
            self.lock_frame = ttk.Frame(self.root)
            self.lock_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            ttk.Label(
                self.lock_frame,
                text="Добро пожаловать в CryptoSafe Manager!",
                font=("Helvetica", 20, "bold")
            ).pack(pady=40)
            ttk.Label(
                self.lock_frame,
                text="Это первый запуск.\nСейчас приложение создаст зашифрованную базу данных.\nПридумайте надёжный мастер-пароль.",
                font=("Helvetica", 12),
                justify="center"
            ).pack(pady=20)
            ttk.Button(
                self.lock_frame,
                text="Создать хранилище",
                command=self.first_run_setup
            ).pack(pady=30)
            self.status_var.set("First run — setup required")

        else:
            self.lock_frame = ttk.Frame(self.root)
            self.lock_frame.pack(fill=tk.BOTH, expand=True)
            ttk.Label(
                self.lock_frame,
                text="CryptoSafe is Locked",
                font=("Helvetica", 24, "bold")
            ).pack(pady=80)
            ttk.Label(
                self.lock_frame,
                text="Введите мастер-пароль для разблокировки хранилища",
                font=("Helvetica", 12)
            ).pack(pady=10)
            ttk.Button(
                self.lock_frame,
                text="Разблокировать",
                command=self.unlock_dialog
            ).pack(pady=20)
            self.update_status()

    def update_status(self):
        if state_manager.is_locked:
            text = "Locked | Vault protected"
        else:
            text = f"Unlocked | User: {state_manager.current_user or 'Unknown'}"
        self.status_var.set(text)

    def unlock_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Unlock Vault")
        dialog.geometry("420x220")
        dialog.transient(self.root)
        dialog.grab_set()
        ttk.Label(dialog, text="Enter master password:", font=("Helvetica", 11)).pack(pady=20)
        pass_entry = ttk.Entry(dialog, show="*", width=40)
        pass_entry.pack(pady=10)
        pass_entry.focus()

        def try_unlock():
            pw = pass_entry.get().strip()
            if not pw:
                messagebox.showwarning("Input required", "Password cannot be empty")
                return
            if len(pw) >= 4:
                from src.core.crypto.secure_memory import secure_wipe_str, secure_zero_bytes
                fake_key = secrets.token_bytes(32)
                secure_zero_bytes(fake_key)
                secure_wipe_str(pw)

                state_manager.is_locked = False
                state_manager.current_user = "demo-user"
                event_bus.publish("UserLoggedIn", {"user": "demo-user"})

                dialog.destroy()
                for widget in self.root.winfo_children():
                    widget.destroy()
                self.__init__(self.root)
            else:
                messagebox.showerror("Access denied", "Incorrect password")
        ttk.Button(dialog, text="Unlock", command=try_unlock).pack(pady=20)

        dialog.bind("<Return>", lambda e: try_unlock())

    def new_vault(self): messagebox.showinfo("Action", "New Vault — not implemented yet")
    def open_vault(self): messagebox.showinfo("Action", "Open Vault — not implemented yet")
    def backup(self): messagebox.showinfo("Action", "Backup — stub")
    def add_entry(self): messagebox.showinfo("Action", "Add Entry — stub")
    def edit_entry(self): messagebox.showinfo("Action", "Edit Entry — stub")
    def delete_entry(self): messagebox.showinfo("Action", "Delete Entry — stub")
    def show_audit_log(self): messagebox.showinfo("Action", "Audit Log — stub (Sprint 5)")
    def show_settings(self): messagebox.showinfo("Action", "Settings — stub")
    def show_about(self):
        messagebox.showinfo("About", "CryptoSafe Manager\nLaboratory work\nSprint 1 — Foundation")

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit CryptoSafe?"):
            self.root.destroy()

    def first_run_setup(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Первый запуск — создание хранилища")
        dialog.geometry("480x320")
        dialog.transient(self.root)
        dialog.grab_set()
        ttk.Label(dialog, text="Придумайте мастер-пароль:", font=("Helvetica", 11)).pack(pady=20)
        pass_entry = ttk.Entry(dialog, show="*", width=40)
        pass_entry.pack(pady=5)
        pass_entry.focus()
        ttk.Label(dialog, text="Подтвердите пароль:", font=("Helvetica", 11)).pack(pady=15)
        confirm_entry = ttk.Entry(dialog, show="*", width=40)
        confirm_entry.pack(pady=5)

        def create_vault():
            pw = pass_entry.get().strip()
            confirm = confirm_entry.get().strip()
            if not pw or not confirm:
                messagebox.showwarning("Ошибка", "Пароль не может быть пустым")
                return
            if pw != confirm:
                messagebox.showerror("Ошибка", "Пароли не совпадают")
                return
            if len(pw) < 8:
                messagebox.showwarning("Слабый пароль", "Рекомендуется использовать пароль минимум 8 символов")
            try:
                open("cryptosafe.db", "a").close()  # создаём пустой файл
                messagebox.showinfo("Успех", "Хранилище создано!\nТеперь можно разблокировать.")
                dialog.destroy()
                for widget in self.root.winfo_children():
                    widget.destroy()
                self.__init__(self.root)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось создать файл базы:\n{e}")

        ttk.Button(dialog, text="Создать", command=create_vault).pack(pady=30)

        dialog.bind("<Return>", lambda e: create_vault())


def main():
    root = tk.Tk()
    app = CryptoSafeMainWindow(root)
    root.mainloop()


if __name__ == "__main__":
    main()