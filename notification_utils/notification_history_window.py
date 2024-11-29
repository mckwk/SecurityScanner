import tkinter as tk
from datetime import datetime
from tkinter import ttk

from vulnerability_utils.vulnerability_detail_window import \
    VulnerabilityDetailWindow


class NotificationHistoryWindow:
    def __init__(self, parent, notification_history):
        self.window = tk.Toplevel(parent)
        self.window.title("Notification History")
        self.notification_history = notification_history
        self._setup_widgets()

    def _setup_widgets(self):
        self.tree = ttk.Treeview(
            self.window,
            columns=(
                "Device Name",
                "CVE ID",
                "Description",
                "Timestamp"),
            show="headings")
        self._configure_treeview()
        self._populate_treeview()
        self.tree.bind("<Double-1>", self.on_item_double_click)

    def _configure_treeview(self):
        headings = ["Device Name", "CVE ID", "Description", "Timestamp"]
        widths = [150, 100, 400, 150]
        for heading, width in zip(headings, widths):
            self.tree.heading(heading, text=heading)
            self.tree.column(heading, width=width, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)

    def _populate_treeview(self):
        for record in self.notification_history:
            if isinstance(record, dict):
                timestamp = self._format_timestamp(
                    record.get('timestamp', 'N/A'))
                self.tree.insert(
                    '',
                    'end',
                    values=(
                        record['device_name'],
                        record['id'],
                        record['description'],
                        timestamp))

    def _format_timestamp(self, timestamp):
        if timestamp != 'N/A':
            try:
                return datetime.fromisoformat(
                    timestamp).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                return 'Invalid format'
        return timestamp

    def on_item_double_click(self, event):
        selected_items = self.tree.selection()
        if not selected_items:
            return

        selected_item = selected_items[0]
        values = self.tree.item(selected_item, "values")
        device_name, cve_id, description, timestamp = values
        details = next(
            (item for item in self.notification_history if item['id'] == cve_id), {})
        details.update({'device_name': device_name, 'timestamp': timestamp})
        VulnerabilityDetailWindow(self.window, details)
