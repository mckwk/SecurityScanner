import json
import logging
import os
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import config
from keyword_cleaner import KeywordCleaner
from log_and_file_managers.logger_manager import LoggerManager

# Configure logging
logger_manager = LoggerManager(config.LOG_FILE)
logger = logger_manager.get_logger()

class DeviceManager:
    def __init__(self, gui):
        self.gui = gui
        self.data_folder = config.DATA_FOLDER
        self.device_info_file = config.DEVICE_INFO_FILE
        self.notification_list_file = config.DATA_FILE
        self.device_info = self.load_device_info()
        self.notification_list = self.load_notification_list()
        self.keyword_cleaner = KeywordCleaner()

    def load_device_info(self):
        if os.path.exists(self.device_info_file):
            with open(self.device_info_file, "r") as file:
                data = json.load(file)
                if isinstance(data, dict):
                    logger.info("Device names loaded successfully")
                    return data
                else:
                    logger.warning("Device names file is not a dictionary")
                    return {}
        logger.warning("Device names file does not exist")
        return {}

    def save_device_info(self):
        os.makedirs(self.data_folder, exist_ok=True)
        with open(self.device_info_file, "w") as file:
            json.dump(self.device_info, file, indent=4)
        logger.info("Device names saved successfully")

    def load_notification_list(self):
        if os.path.exists(self.notification_list_file):
            with open(self.notification_list_file, "r") as file:
                logger.info("Devices loaded successfully")
                return json.load(file)
        logger.warning("Devices file does not exist")
        return []

    def save_notification_list(self):
        os.makedirs(self.data_folder, exist_ok=True)
        with open(self.notification_list_file, "w") as file:
            json.dump(self.notification_list, file, indent=4)
        logger.info("Devices saved successfully")

    def on_device_select(self, event):
        selected_item = self.gui.device_tree.selection()
        if selected_item:
            device = self.gui.device_tree.item(selected_item[0], "values")
            self.display_device_vulnerabilities(device)

    def display_device_vulnerabilities(self, device):
        ip, mac, vendor, OS, device_name, vulnerabilities = device
        self.gui.vulnerability_text.delete('1.0', tk.END)
        self.gui.vulnerability_text.insert(
            tk.END, f"Vulnerabilities for device {ip} (Vendor: {vendor}):\n{'=' * 80}\n")
        try:
            vulnerabilities = eval(vulnerabilities)
            if not isinstance(vulnerabilities, list):
                vulnerabilities = []
        except:
            vulnerabilities = []
        self.display_vulnerabilities(vulnerabilities, ip, vendor)

    def display_vulnerabilities(self, vulnerabilities, ip, vendor):
        if not vulnerabilities:
            self.gui.vulnerability_text.insert(
                tk.END, f"No vulnerabilities found for the device {ip} (Vendor: {vendor})\n")
            return
        for vuln in vulnerabilities:
            self.insert_vulnerability_text(vuln)

    def insert_vulnerability_text(self, vuln):
        cve = vuln.get('cve', {})
        cve_id = cve.get('id', 'Unknown ID')
        description = cve.get('descriptions', 'No description available')
        severity = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity', 'Unknown')
        published_date = cve.get('published', 'Unknown')
        try:
            published_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%M:%S.%f').strftime('%Y-%m-%d %H:%M')
        except ValueError:
            pass
        self.gui.vulnerability_text.insert(
            tk.END,
            f"CVE ID: {cve_id}\nDescription: {description}\nSeverity: {severity}\nPublished Date: {published_date}\n{'-' * 80}\n")

    def process_device(self, device):
        vendor, OS, mac = device['vendor'], device['OS'], device['mac']
        device_info = self.get_device_info(mac, device)
        vulnerabilities = self.get_vulnerabilities(vendor, OS, device_info['device_name'])
        self.insert_device_to_tree(device, device_info, vulnerabilities)
        self.update_notification_list(vendor, OS, device_info['device_name'])
        self.save_notification_list()
        self.update_device_info(mac, device, device_info, vulnerabilities)
        self.save_device_info()
        logger.info("Processed device: %s", device)

    def get_device_info(self, mac, device):
        device_info = self.device_info.get(mac, {})
        if isinstance(device_info, str):
            device_info = {"device_name": device_info}
        device_info['device_name'] = device_info.get('device_name', device.get('device_name', 'unknown'))
        return device_info

    def get_vulnerabilities(self, vendor, OS, device_name):
        if vendor == "Unknown":
            return []
        if device_name.lower() != "unknown":
            return self.gui.vulnerability_checker.search_vulnerabilities(OS, vendor, device_name)
        return self.gui.vulnerability_checker.search_vulnerabilities(OS, self.gui.vulnerability_checker.extract_keyword(vendor))

    def insert_device_to_tree(self, device, device_info, vulnerabilities):
        self.gui.device_tree.insert("", tk.END, values=(
            device['ip'], device['mac'], device['vendor'], device['OS'], device_info['device_name'], str(vulnerabilities)))

    def update_notification_list(self, vendor, OS, device_name):
        cleaned_vendor = self.keyword_cleaner.clean_vendor_name(vendor)
        keyword_combinations = [
            f"{cleaned_vendor} {OS} {device_name}",
            f"{cleaned_vendor} {device_name}",
            OS,
            device_name
        ]
        for keyword in keyword_combinations:
            if keyword.lower() != "unknown" and keyword not in self.notification_list:
                self.notification_list.append(keyword)

    def update_device_info(self, mac, device, device_info, vulnerabilities):
        self.device_info[mac] = {
            "ip": device['ip'],
            "vendor": device['vendor'],
            "OS": device['OS'],
            "device_name": device_info['device_name'],
            "vulnerabilities": vulnerabilities
        }

    def search_vulnerabilities(self, user_input):
        if not user_input:
            logger.warning("No user input provided for vulnerability search")
            return
        self.gui.vulnerability_text.delete('1.0', tk.END)
        self.gui.vulnerability_text.insert(
            tk.END, f"Searching vulnerabilities for: {user_input}\n{'=' * 80}\n")
        vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(user_input, "Unknown")
        self.display_vulnerabilities(vulnerabilities, "N/A", user_input)
        logger.info("Searched vulnerabilities for: %s", user_input)

    def on_double_click(self, event):
        selected_item = self.gui.device_tree.selection()
        if selected_item:
            item = selected_item[0]
            column = self.gui.device_tree.identify_column(event.x)
            self.edit_device_name(item, column)

    def edit_device_name(self, item, column):
        entry = ttk.Entry(self.gui.device_tree)
        entry.grid(row=0, column=0)
        entry.focus_set()
        entry.bind("<Return>", lambda e: self.save_edit(e, item, column, entry))

    def save_edit(self, event, item, column, entry):
        new_value = entry.get()
        self.gui.device_tree.set(item, column, new_value)
        entry.destroy()
        mac = self.gui.device_tree.item(item, "values")[1]
        self.device_info[mac]["device_name"] = new_value
        self.save_device_info()
        self.gui.vulnerability_text.delete('1.0', tk.END)
        vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(new_value, "Unknown")
        self.gui.device_tree.set(item, '#6', str(vulnerabilities))
        self.device_info[mac]["vulnerabilities"] = vulnerabilities
        self.save_device_info()
        self.display_vulnerabilities(vulnerabilities, "N/A", new_value)
        logger.info("Edited device name for MAC %s: %s", mac, new_value)