import tkinter as tk
from tkinter import ttk
import json
import os

class NotificationManager:
    def __init__(self, notification_frame):
        self.notification_frame = notification_frame
        self.data_folder = 'user_data'
        self.data_file = os.path.join(self.data_folder, 'devices.json')
        self._setup_widgets()
        self.load_devices_from_json()

    def _setup_widgets(self):
        self.add_device_entry = ttk.Entry(self.notification_frame, width=50)
        self.add_device_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.add_device_button = ttk.Button(self.notification_frame, text="Add Device", command=self.add_device_to_notification)
        self.add_device_button.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.delete_device_button = ttk.Button(self.notification_frame, text="Delete Device", command=self.delete_device_from_notification)
        self.delete_device_button.grid(row=1, column=1, padx=10, pady=10, sticky="w")

        self.notification_tree = ttk.Treeview(self.notification_frame, columns=("IP", "MAC", "Vendor", "Model", "Product ID"), show="tree")
        self.notification_tree.heading("IP", text="IP Address")
        self.notification_tree.heading("MAC", text="MAC Address")
        self.notification_tree.heading("Vendor", text="Vendor")
        self.notification_tree.heading("Model", text="Model")
        self.notification_tree.heading("Product ID", text="Product ID")
        self.notification_tree.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")

        self.notification_tree.column("IP", width=150, anchor="w")
        self.notification_tree.column("MAC", width=150, anchor="w")
        self.notification_tree.column("Vendor", width=150, anchor="w")
        self.notification_tree.column("Model", width=150, anchor="w")
        self.notification_tree.column("Product ID", width=150, anchor="w")

    def add_device_to_notification(self):
        device_info = self.add_device_entry.get()
        if device_info:
            device_data = device_info.split(',')
            self.notification_tree.insert('', 'end', values=device_data)
            self.save_devices_to_json()

    def delete_device_from_notification(self):
        selected_item = self.notification_tree.selection()
        if selected_item:
            self.notification_tree.delete(selected_item)
            self.save_devices_to_json()

    def save_devices_to_json(self):
        if not os.path.exists(self.data_folder):
            os.makedirs(self.data_folder)
        devices = []
        for item in self.notification_tree.get_children():
            devices.append(self.notification_tree.item(item, 'values'))
        with open(self.data_file, 'w') as f:
            json.dump(devices, f, indent=4)

    def load_devices_from_json(self):
        if not os.path.exists(self.data_file):
            return
        try:
            with open(self.data_file, 'r') as f:
                devices = json.load(f)
                self.notification_tree.delete(*self.notification_tree.get_children())
                for device in devices:
                    self.notification_tree.insert('', 'end', values=device)
        except FileNotFoundError:
            pass