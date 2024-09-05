import tkinter as tk
from tkinter import ttk
from vulnerability_detail_window import VulnerabilityDetailWindow

class NotificationHistoryWindow:
    def __init__(self, parent, notification_history):
        self.window = tk.Toplevel(parent)
        self.window.title("Notification History")
        self.notification_history = notification_history
        self._setup_widgets()

    def _setup_widgets(self):
        self.tree = ttk.Treeview(self.window, columns=("Device Name", "CVE ID", "Description"), show="headings")
        self.tree.heading("Device Name", text="Device Name")
        self.tree.heading("CVE ID", text="CVE ID")
        self.tree.heading("Description", text="Description")
        self.tree.column("Device Name", width=150, anchor="w")
        self.tree.column("CVE ID", width=100, anchor="w")
        self.tree.column("Description", width=400, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)

        for record in self.notification_history:
            if isinstance(record, dict):
                self.tree.insert('', 'end', values=(record['device_name'], record['id'], record['description']))

        self.tree.bind("<Double-1>", self.on_item_double_click)

    def on_item_double_click(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return  # No item selected, do nothing

        selected_item = selected_items[0]
        values = self.tree.item(selected_item, "values")
        device_name, cve_id, description = values
        details = next((item for item in self.notification_history if item['id'] == cve_id), {})
        details['device_name'] = device_name
        VulnerabilityDetailWindow(self.window, details)