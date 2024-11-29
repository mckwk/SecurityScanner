import tkinter as tk
from tkinter import ttk


class ProgressWindow:
    def __init__(self, root, title, cancel_callback):
        self.progress_window = tk.Toplevel(root)
        self.progress_window.title(title)
        self.progress_window.geometry("300x150")
        self.progress_window.resizable(False, False)
        self.cancel_callback = cancel_callback
        self._center_window(root)
        self._setup_widgets(title)

    def _center_window(self, root):
        root.update_idletasks()
        x = root.winfo_x() + (root.winfo_width() // 2) - 150
        y = root.winfo_y() + (root.winfo_height() // 2) - 75
        self.progress_window.geometry(f"+{x}+{y}")

    def _setup_widgets(self, title):
        label = ttk.Label(self.progress_window, text=f"{title}...")
        label.pack(pady=10)
        self.progress_bar = ttk.Progressbar(
            self.progress_window, mode='indeterminate')
        self.progress_bar.pack(pady=10)
        self.progress_bar.start(interval=10)
        self.cancel_button = ttk.Button(
            self.progress_window, text="Cancel", command=self._cancel)
        self.cancel_button.pack(pady=10)

    def _cancel(self):
        self.cancel_callback()
        self.destroy()

    def destroy(self):
        self.progress_window.destroy()
