import os
import threading
import tkinter as tk
import webbrowser
from datetime import datetime, timedelta
from tkinter import messagebox
import sched

from plyer import notification

from log_and_file_managers.data_manager import DataManager
from log_and_file_managers.logger_manager import LoggerManager
from notification_utils.notification_history_window import NotificationHistoryWindow
from notification_utils.notification_widgets import NotificationWidgets
from UI.progress_window import ProgressWindow
from vulnerability_utils.vulnerability_checker import VulnerabilityChecker


class NotificationManager:
    def __init__(self, notification_frame):
        from config import DATA_FILE, DATA_FOLDER, HISTORY_FILE, LOG_FILE

        self.notification_frame = notification_frame
        self.data_folder = DATA_FOLDER
        self.data_file = DATA_FILE
        self.log_file = LOG_FILE
        self.history_file = HISTORY_FILE
        self.logger_manager = LoggerManager(self.log_file)
        self.logger = self.logger_manager.get_logger()
        self.vulnerability_checker = VulnerabilityChecker()
        self.data_manager = DataManager(
            self.data_folder, self.data_file, self.history_file, self.logger)
        self.notification_history = self.data_manager.load_notification_history()
        self.widgets = NotificationWidgets(
            notification_frame,
            self.add_device_to_notification,
            self.delete_device_from_notification,
            self.send_notifications,
            self.open_log_file,
            self.open_notification_history,
            self.schedule_notifications
        )
        self.load_devices_from_json()

        # Initialize scheduler
        self.scheduler = sched.scheduler()
        self.cancel_event = threading.Event()

    def add_device_to_notification(self):
        device_name = self.widgets.add_device_entry.get().strip()
        if not device_name:
            messagebox.showerror("Error", "Device name cannot be empty")
            return

        if any(self.widgets.notification_tree.item(item, 'values')[0] == device_name for item in self.widgets.notification_tree.get_children()):
            messagebox.showerror("Error", "Device name already exists")
            return

        self.widgets.notification_tree.insert('', 'end', values=(device_name,))
        self.save_devices_to_json()
        self.widgets.add_device_entry.delete(0, tk.END)
        self.logger.info(f"Device '{device_name}' added to notification list.")

    def delete_device_from_notification(self):
        selected_item = self.widgets.notification_tree.selection()
        if not selected_item:
            messagebox.showerror("Error", "No device selected")
            return

        self.widgets.notification_tree.delete(selected_item)
        self.save_devices_to_json()
        self.logger.info(
            f"Device '{selected_item}' deleted from notification list.")

    def save_devices_to_json(self):
        devices = [self.widgets.notification_tree.item(
            item, 'values')[0] for item in self.widgets.notification_tree.get_children()]
        self.data_manager.save_devices_to_json(devices)

    def load_devices_from_json(self):
        devices = self.data_manager.load_devices_from_json()
        self.widgets.notification_tree.delete(
            *self.widgets.notification_tree.get_children())
        for device in devices:
            self.widgets.notification_tree.insert('', 'end', values=(device,))

    def gather_vulnerabilities_summary(self):
        start_year_str = self.widgets.start_with_entry.get().strip() or '1999'
        start_year = int(start_year_str)

        vulnerabilities = []
        for item in self.widgets.notification_tree.get_children():
            if self.cancel_event.is_set():
                break
            device_name = self.widgets.notification_tree.item(item, 'values')[0]
            found_vulnerabilities = self.vulnerability_checker.search_vulnerabilities(
                model=device_name, vendor="unknown", max_results=10)
            for vulnerability in found_vulnerabilities:
                if self.cancel_event.is_set():
                    break
                cve = vulnerability.get('cve', {})
                published_date_str = cve.get('published', 'Unknown')
                try:
                    published_date = datetime.strptime(
                        published_date_str, '%Y-%m-%dT%H:%M:%S.%f')
                except ValueError:
                    published_date = None

                if published_date and published_date.year >= start_year:
                    cve_id = cve.get('id', 'Unknown ID')
                    description = cve.get('descriptions', [{}])[0].get(
                        'value', 'No description available')
                    metrics = cve.get('metrics', {}).get(
                        'cvssMetricV2', [{}])[0]
                    severity = metrics.get('baseSeverity', 'Unknown')
                    impact_score = metrics.get('impactScore', 'Unknown')
                    exploitability_score = metrics.get(
                        'exploitabilityScore', 'Unknown')
                    references = [ref.get('url', 'No URL')
                                  for ref in cve.get('references', [])]
                    vulnerabilities.append({
                        'device_name': device_name,
                        'id': cve_id,
                        'description': description,
                        'published': published_date_str,
                        'last_modified': cve.get('lastModified', 'Unknown'),
                        'severity': severity,
                        'impact_score': impact_score,
                        'exploitability_score': exploitability_score,
                        'references': references
                    })
        return vulnerabilities

    def send_notifications(self):
        self.cancel_event.clear()
        progress_window = ProgressWindow(
            self.notification_frame, "Searching for Vulnerabilities", self.cancel_scan)
        threading.Thread(target=self._send_notifications,
                         args=(progress_window,)).start()

    def _send_notifications(self, progress_window):
        try:
            self.logger.info("\n" + "_" * 50 + "\n")
            start_time = datetime.now()
            self.logger.info(f"Scan started at {start_time}")
            vulnerabilities = self.gather_vulnerabilities_summary()
            progress_window.destroy()
            if self.cancel_event.is_set():
                self.logger.info("Scan was canceled.")
                return
            new_vulnerabilities = []
            if vulnerabilities:
                for vulnerability in vulnerabilities:
                    device_name = vulnerability['device_name']
                    cve_id = vulnerability['id']
                    description = vulnerability['description']
                    max_description_length = 256 - \
                        len(cve_id) - len(device_name) - 100
                    truncated_description = (description[:max_description_length] + '...') if len(
                        description) > max_description_length else description
                    if not any(vuln['id'] == cve_id for vuln in self.notification_history):
                        notification.notify(
                            title=f"Vulnerability found in {device_name}",
                            message=f"{cve_id}: {truncated_description}",
                            timeout=10,
                            app_name="Security Scanner"
                        )
                        self.notification_history.append(vulnerability)
                        new_vulnerabilities.append(vulnerability)
                        self.logger.info(
                            f"Vulnerability found in {device_name}:\nCVE ID: {cve_id}\nDescription: {description}\n")
                self.save_notification_history()
                if not new_vulnerabilities:
                    notification.notify(
                        title="No New Vulnerabilities Found",
                        message="All vulnerabilities were previously sent.",
                        timeout=10
                    )
                self.logger.info(
                    "Notifications sent for found vulnerabilities.")
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
            self.logger_manager.prepend_log_file()
        except Exception as e:
            progress_window.destroy()
            messagebox.showerror(
                "Error", f"An error occurred while sending notifications: {e}")
            self.logger.error(f"Error sending notifications: {e}")

        # Reschedule the next notification
        interval = int(self.widgets.interval_combobox.get()) * 60
        self.schedule_notifications(interval=interval)

    def cancel_scan(self):
        self.cancel_event.set()

    def schedule_notifications(self, interval=None):
        if interval is None:
            interval = int(self.widgets.interval_combobox.get()) * 60
        self.scheduler.enter(interval, 1, self.send_notifications)
        threading.Thread(target=self.scheduler.run).start()

    def save_notification_history(self):
        self.data_manager.save_notification_history(self.notification_history)

    def load_notification_history(self):
        return self.data_manager.load_notification_history()

    def open_log_file(self):
        log_file_path = os.path.abspath(self.log_file)
        webbrowser.open(f'file:///{log_file_path}')

    def open_notification_history(self):
        NotificationHistoryWindow(
            self.notification_frame, self.notification_history)