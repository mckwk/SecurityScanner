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
        self.add_device_entry = ttk.Entry(self.notification_frame, width=50)
        self.add_device_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.add_device_entry.bind("<Return>", lambda event: self.add_device_callback())

        self.add_device_button = ttk.Button(self.notification_frame, text="Add Device", command=self.add_device_callback)
        self.add_device_button.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.delete_device_button = ttk.Button(self.notification_frame, text="Delete Device", command=self.delete_device_callback)
        self.delete_device_button.grid(row=0, column=2, padx=10, pady=10, sticky="w")

        self.notification_tree = ttk.Treeview(self.notification_frame, columns=("Device Name",), show="headings")
        self.notification_tree.heading("Device Name", text="Device Name")
        self.notification_tree.column("Device Name", width=300, anchor="w")
        self.notification_tree.grid(row=1, column=0, padx=10, pady=10, sticky="nsew", columnspan=3)

        self.send_notifications_button = ttk.Button(self.notification_frame, text="Send Notifications", command=self.send_notifications_callback)
        self.send_notifications_button.grid(row=2, column=0, padx=10, pady=10, sticky="ew", columnspan=1)

        self.start_with_label = ttk.Label(self.notification_frame, text="Start With (year):")
        self.start_with_label.grid(row=2, column=1, padx=10, pady=10, sticky="e")

        self.start_with_entry = ttk.Entry(self.notification_frame, width=10)
        self.start_with_entry.grid(row=2, column=2, padx=10, pady=10, sticky="w")

        self.open_log_button = ttk.Button(self.notification_frame, text="Open Log File", command=self.open_log_callback)
        self.open_log_button.grid(row=3, column=0, padx=10, pady=10, sticky="ew", columnspan=3)

        self.open_history_button = ttk.Button(self.notification_frame, text="Open Notification History", command=self.open_history_callback)
        self.open_history_button.grid(row=4, column=0, padx=10, pady=10, sticky="ew", columnspan=3)

        self.notification_frame.grid_rowconfigure(1, weight=1)
        self.notification_frame.grid_columnconfigure(0, weight=1)