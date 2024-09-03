import tkinter as tk
from tkinter import ttk, messagebox
import json
import os
from datetime import datetime
from plyer import notification
from vulnerability_checker import VulnerabilityChecker
from progress_window import ProgressWindow
import threading
import logging
import webbrowser
import io

class CustomFilter(logging.Filter):
    def filter(self, record):
        # Exclude specific log messages
        return "Starting new HTTPS connection" not in record.getMessage()

class NotificationManager:
    def __init__(self, notification_frame):
        self.notification_frame = notification_frame
        self.data_folder = 'user_data'
        self.data_file = os.path.join(self.data_folder, 'devices.json')
        self.log_file = os.path.join(self.data_folder, 'notification_manager.log')
        self.log_stream = io.StringIO()
        self._setup_logging()
        self.vulnerability_checker = VulnerabilityChecker()
        self._setup_widgets()
        self.load_devices_from_json()

    def _setup_logging(self):
        os.makedirs(self.data_folder, exist_ok=True)
        if not os.path.exists(self.log_file):
            with open(self.log_file, 'w') as f:
                pass  # Create the file if it doesn't exist

        # Create a custom logger
        self.logger = logging.getLogger('NotificationManager')
        self.logger.setLevel(logging.DEBUG)

        # Create handlers
        stream_handler = logging.StreamHandler(self.log_stream)
        stream_handler.setLevel(logging.DEBUG)
        stream_handler.addFilter(CustomFilter())

        # Create formatters and add it to handlers
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        stream_handler.setFormatter(formatter)

        # Add handlers to the logger
        self.logger.addHandler(stream_handler)
        self.logger.info("\n" + "_" * 50 + "\n")
        self.logger.debug("Logging setup complete.")

    def _setup_widgets(self):
        self.add_device_entry = ttk.Entry(self.notification_frame, width=50)
        self.add_device_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.add_device_entry.bind("<Return>", lambda event: self.add_device_to_notification())

        self.add_device_button = ttk.Button(self.notification_frame, text="Add Device", command=self.add_device_to_notification)
        self.add_device_button.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        self.delete_device_button = ttk.Button(self.notification_frame, text="Delete Device", command=self.delete_device_from_notification)
        self.delete_device_button.grid(row=0, column=2, padx=10, pady=10, sticky="w")

        self.notification_tree = ttk.Treeview(self.notification_frame, columns=("Device Name",), show="headings")
        self.notification_tree.heading("Device Name", text="Device Name")
        self.notification_tree.column("Device Name", width=300, anchor="w")
        self.notification_tree.grid(row=1, column=0, padx=10, pady=10, sticky="nsew", columnspan=3)

        self.send_notifications_button = ttk.Button(self.notification_frame, text="Send Notifications", command=self.send_notifications)
        self.send_notifications_button.grid(row=2, column=0, padx=10, pady=10, sticky="ew", columnspan=3)

        self.open_log_button = ttk.Button(self.notification_frame, text="Open Log File", command=self.open_log_file)
        self.open_log_button.grid(row=3, column=0, padx=10, pady=10, sticky="ew", columnspan=3)

        self.notification_frame.grid_rowconfigure(1, weight=1)
        self.notification_frame.grid_columnconfigure(0, weight=1)

    def add_device_to_notification(self):
        device_name = self.add_device_entry.get().strip()
        if not device_name:
            messagebox.showerror("Error", "Device name cannot be empty")
            return

        if any(self.notification_tree.item(item, 'values')[0] == device_name for item in self.notification_tree.get_children()):
            messagebox.showerror("Error", "Device name already exists")
            return

        self.notification_tree.insert('', 'end', values=(device_name,))
        self.save_devices_to_json()
        self.add_device_entry.delete(0, tk.END)
        self.logger.info(f"Device '{device_name}' added to notification list.")

    def delete_device_from_notification(self):
        selected_item = self.notification_tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No device selected")
            return

        self.notification_tree.delete(selected_item)
        self.save_devices_to_json()
        self.logger.info(f"Device '{selected_item}' deleted from notification list.")

    def save_devices_to_json(self):
        os.makedirs(self.data_folder, exist_ok=True)
        devices = [self.notification_tree.item(item, 'values')[0] for item in self.notification_tree.get_children()]
        with open(self.data_file, 'w') as f:
            json.dump(devices, f, indent=4)
        self.logger.info("Devices saved to JSON file.")

    def load_devices_from_json(self):
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    devices = json.load(f)
                    self.notification_tree.delete(*self.notification_tree.get_children())
                    for device in devices:
                        self.notification_tree.insert('', 'end', values=(device,))
                self.logger.info("Devices loaded from JSON file.")
            except (FileNotFoundError, json.JSONDecodeError) as e:
                self.logger.error(f"Error loading devices from JSON file: {e}")

    def gather_vulnerabilities_summary(self):
        current_year = datetime.now().year
        vulnerabilities = []
        for item in self.notification_tree.get_children():
            device_name = self.notification_tree.item(item, 'values')[0]
            found_vulnerabilities = self.vulnerability_checker.search_vulnerabilities(model=device_name, vendor="unknown", max_results=10)
            for vulnerability in found_vulnerabilities:
                cve = vulnerability.get('cve', {})
                if cve.get('published', '').startswith(str(current_year)):
                    cve_id = cve.get('id', 'Unknown ID')
                    description = cve.get('descriptions', [{}])[0].get('value', 'No description available')
                    vulnerabilities.append((device_name, cve_id, description))
        return vulnerabilities

    def send_notifications(self):
        progress_window = ProgressWindow(self.notification_frame, "Searching for Vulnerabilities")
        threading.Thread(target=self._send_notifications, args=(progress_window,)).start()

    def _send_notifications(self, progress_window):
        try:
            self.logger.info("\n" + "_" * 50 + "\n")
            start_time = datetime.now()
            self.logger.info(f"Scan started at {start_time}")
            vulnerabilities = self.gather_vulnerabilities_summary()
            progress_window.destroy()
            if vulnerabilities:
                for device_name, cve_id, description in vulnerabilities:
                    max_description_length = 256 - len(cve_id) - len(device_name) - 100
                    truncated_description = (description[:max_description_length] + '...') if len(description) > max_description_length else description
                    notification.notify(
                        title=f"Vulnerability found in {device_name}",
                        message=f"{cve_id}: {truncated_description}",
                        timeout=10,
                        app_name="Security Scanner"
                    )
                    self.logger.info(f"Vulnerability found in {device_name}:\nCVE ID: {cve_id}\nDescription: {description}\n")
                self.logger.info("Notifications sent for found vulnerabilities.")
            else:
                notification.notify(
                    title="No Vulnerabilities Found",
                    message="No vulnerabilities were found for the devices this year.",
                    timeout=10
                )
                self.logger.info("No vulnerabilities found for the devices.")
            end_time = datetime.now()
            self.logger.info(f"Scan ended at {end_time}")
            self.logger.info(f"Total scan duration: {end_time - start_time}")
            self.logger.debug("Flushing logs.")
            self._prepend_log_file()
        except Exception as e:
            progress_window.destroy()
            messagebox.showerror("Error", f"An error occurred while sending notifications: {e}")
            self.logger.error(f"Error sending notifications: {e}")

    def _prepend_log_file(self):
        new_logs = self.log_stream.getvalue()
        with open(self.log_file, 'r') as f:
            existing_logs = f.read()
        with open(self.log_file, 'w') as f:
            f.write(new_logs + existing_logs)
        self.log_stream.seek(0)
        self.log_stream.truncate(0)

    def open_log_file(self):
        log_file_path = os.path.abspath(self.log_file)
        webbrowser.open(f'file:///{log_file_path}')