# data_manager.py
import json
import os
from datetime import datetime

class DataManager:
    def __init__(self, data_folder, data_file, history_file, logger):
        self.data_folder = data_folder
        self.data_file = data_file
        self.history_file = history_file
        self.logger = logger

    def save_devices_to_json(self, devices):
        os.makedirs(self.data_folder, exist_ok=True)
        with open(self.data_file, 'w') as f:
            json.dump(devices, f, indent=4)
        self.logger.info("Devices saved to JSON file.")

    def load_devices_from_json(self):
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, 'r') as f:
                    devices = json.load(f)
                self.logger.info("Devices loaded from JSON file.")
                return devices
            except (FileNotFoundError, json.JSONDecodeError) as e:
                self.logger.error(f"Error loading devices from JSON file: {e}")
        return []

    def save_notification_history(self, notification_history):
        os.makedirs(self.data_folder, exist_ok=True)
        unique_history = {v['id']: v for v in notification_history}.values()
        for entry in unique_history:
            entry['timestamp'] = datetime.now().isoformat()
        with open(self.history_file, 'w') as f:
            json.dump(list(unique_history), f, indent=4)
        self.logger.info("Notification history saved to JSON file.")

    def load_notification_history(self):
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    return json.load(f)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                self.logger.error(f"Error loading notification history from JSON file: {e}")
        return []