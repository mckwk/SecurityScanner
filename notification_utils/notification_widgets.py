import tkinter as tk
from tkinter import ttk


class NotificationWidgets:
    def __init__(self, notification_frame, add_device_callback, delete_device_callback, send_notifications_callback, open_log_callback, open_history_callback):
        self.notification_frame = notification_frame
        self.add_device_callback = add_device_callback
        self.delete_device_callback = delete_device_callback
        self.send_notifications_callback = send_notifications_callback
        self.open_log_callback = open_log_callback
        self.open_history_callback = open_history_callback
        self.setup()

    def setup(self):
        self.add_device_entry = self._create_entry(
            0, 0, 50, self.add_device_callback)
        self.add_device_button = self._create_button(
            "Add Device", self.add_device_callback, 0, 1)
        self.delete_device_button = self._create_button(
            "Delete Device", self.delete_device_callback, 0, 2)
        self.notification_tree = self._create_treeview(1, 0, 3)
        self.send_notifications_button = self._create_button(
            "Send Notifications", self.send_notifications_callback, 2, 0)
        self.start_with_label = self._create_label("Start With (year):", 2, 1)
        self.start_with_entry = self._create_entry(2, 2, 10)
        self.open_log_button = self._create_button(
            "Open Log File", self.open_log_callback, 3, 0, 3)
        self.open_history_button = self._create_button(
            "Open Notification History", self.open_history_callback, 4, 0, 3)
        self.notification_frame.grid_rowconfigure(1, weight=1)
        self.notification_frame.grid_columnconfigure(0, weight=1)

    def _create_entry(self, row, column, width, callback=None):
        entry = ttk.Entry(self.notification_frame, width=width)
        entry.grid(row=row, column=column, padx=10, pady=10, sticky="ew")
        if callback:
            entry.bind("<Return>", lambda event: callback())
        return entry

    def _create_button(self, text, command, row, column, columnspan=1):
        button = ttk.Button(self.notification_frame,
                            text=text, command=command)
        button.grid(row=row, column=column, padx=10, pady=10,
                    sticky="ew", columnspan=columnspan)
        return button

    def _create_treeview(self, row, column, columnspan):
        tree = ttk.Treeview(self.notification_frame, columns=(
            "Device Name",), show="headings")
        tree.heading("Device Name", text="Device Name")
        tree.column("Device Name", width=300, anchor="w")
        tree.grid(row=row, column=column, padx=10, pady=10,
                  sticky="nsew", columnspan=columnspan)
        return tree

    def _create_label(self, text, row, column):
        label = ttk.Label(self.notification_frame, text=text)
        label.grid(row=row, column=column, padx=10, pady=10, sticky="e")
        return label
