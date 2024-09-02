import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
from datetime import datetime
from plyer import notification
from vulnerability_checker import VulnerabilityChecker
from progress_window import ProgressWindow
import threading

class NotificationManager:
    def __init__(self, notification_frame):
        self.notification_frame = notification_frame
        self.data_folder = 'user_data'
        self.data_file = os.path.join(self.data_folder, 'devices.json')
        self.vulnerability_checker = VulnerabilityChecker()
        self._setup_widgets()
        self.load_devices_from_json()

    def _setup_widgets(self):
        self.add_device_entry = ttk.Entry(self.notification_frame, width=50)
        self.add_device_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.add_device_button = ttk.Button(self.notification_frame, text="Add Device", command=self.add_device_to_notification)
        self.add_device_button.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.delete_device_button = ttk.Button(self.notification_frame, text="Delete Device", command=self.delete_device_from_notification)
        self.delete_device_button.grid(row=0, column=2, padx=10, pady=10, sticky="w")

        self.notification_tree = ttk.Treeview(self.notification_frame, columns=("Device Name",), show="headings")
        self.notification_tree.heading("Device Name", text="Device Name")
        self.notification_tree.grid(row=1, column=0, padx=10, pady=10, sticky="nsew", columnspan=3)

        self.notification_tree.column("Device Name", width=300, anchor="w")

        self.send_notifications_button = ttk.Button(self.notification_frame, text="Send Notifications", command=self.send_notifications)
        self.send_notifications_button.grid(row=2, column=0, padx=10, pady=10, sticky="ew", columnspan=3)

    def add_device_to_notification(self):
        device_name = self.add_device_entry.get()
        if device_name:
            # Check for duplicate entries
            for item in self.notification_tree.get_children():
                if self.notification_tree.item(item, 'values')[0] == device_name:
                    messagebox.showerror("Error", "Device name already exists")
                    return
            self.notification_tree.insert('', 'end', values=(device_name,))
            self.save_devices_to_json()
        else:
            messagebox.showerror("Error", "Device name cannot be empty")

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
            devices.append(self.notification_tree.item(item, 'values')[0])
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
                    self.notification_tree.insert('', 'end', values=(device,))
        except FileNotFoundError:
            pass

    def gather_vulnerabilities_summary(self):
        current_year = datetime.now().year
        vulnerabilities = []
        for item in self.notification_tree.get_children():
            device_name = self.notification_tree.item(item, 'values')[0]
            # Search for vulnerabilities using the device name as-is
            found_vulnerabilities = self.vulnerability_checker.search_vulnerabilities(model=device_name, vendor="unknown", max_results=10)
            for vulnerability in found_vulnerabilities:
                cve = vulnerability.get('cve', {})
                published_date = cve.get('published', '')
                if published_date.startswith(str(current_year)):
                    cve_id = cve.get('id', 'Unknown ID')
                    description_data = cve.get('descriptions', [])
                    description = description_data[0]['value'] if description_data else 'No description available'
                    vulnerabilities.append((device_name, cve_id, description))
        return vulnerabilities

    def send_notifications(self):
        progress_window = ProgressWindow(self.notification_frame, "Searching for Vulnerabilities")
        threading.Thread(target=self._send_notifications, args=(progress_window,)).start()

    def _send_notifications(self, progress_window):
        vulnerabilities = self.gather_vulnerabilities_summary()
        progress_window.destroy()
        if vulnerabilities:
            for device_name, cve_id, description in vulnerabilities:
                # Calculate the maximum length for the description
                max_description_length = 256 - len(cve_id) - len(device_name) - 100  # Adjust for other parts of the message
                truncated_description = (description[:max_description_length] + '...') if len(description) > max_description_length else description
                notification.notify(
                    title=f"Vulnerability found in {device_name}",
                    message=f"{cve_id}: {truncated_description}",
                    timeout=10,
                    app_name="Security Scanner"
                )
                # Store the full description to show later
                self.show_full_description(cve_id, description)
        else:
            notification.notify(
                title="No Vulnerabilities Found",
                message="No vulnerabilities were found for the devices this year.",
                timeout=10
            )

    def show_full_description(self, cve_id, description):
        # Display the full description in a message box
        messagebox.showinfo(title=f"Full Description for {cve_id}", message=description)