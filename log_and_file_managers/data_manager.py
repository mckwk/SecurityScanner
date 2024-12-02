import json
import os
from datetime import datetime


class DataManager:
    def __init__(self, data_folder, notification_list_file, history_file, logger):
        self.data_folder = data_folder
        self.notification_list_file = notification_list_file
        self.history_file = history_file
        self.logger = logger

    def save_notification_list_to_json(self, notification_list):
        os.makedirs(self.data_folder, exist_ok=True)
        with open(self.notification_list_file, 'w') as f:
            json.dump(notification_list, f, indent=4)
        self.logger.info("Devices saved to JSON file.")

    def load_notification_list_from_json(self):
        if os.path.exists(self.notification_list_file):
            try:
                with open(self.notification_list_file, 'r') as f:
                    notification_list = json.load(f)
                self.logger.info("Devices loaded from JSON file.")
                return notification_list
            except (FileNotFoundError, json.JSONDecodeError) as e:
                self.logger.error(
                    f"Error loading notification_list from JSON file: {e}")
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
                self.logger.error(
                    f"Error loading notification history from JSON file: {e}")
        return []
