import tkinter as tk
from tkinter import ttk

class ProgressWindow:
    def __init__(self, root, title):
        self.progress_window = tk.Toplevel(root)
        self.progress_window.title(title)
        self.progress_window.geometry("300x100")
        self.progress_window.resizable(False, False)
        self.center_window(root)
        label = ttk.Label(self.progress_window, text=f"{title}...")
        label.pack(pady=10)
        self.progress_bar = ttk.Progressbar(self.progress_window, mode='indeterminate')
        self.progress_bar.pack(pady=10)
        self.progress_bar.start(interval=10)

    def center_window(self, root):
        root.update_idletasks()
        x = root.winfo_x() + (root.winfo_width() // 2) - (300 // 2)
        y = root.winfo_y() + (root.winfo_height() // 2) - (100 // 2)
        self.progress_window.geometry(f"+{x}+{y}")

    def destroy(self):
        self.progress_window.destroy()