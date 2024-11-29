import json
import os
import tkinter as tk
from datetime import datetime
from tkinter import ttk
import logging

import config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DeviceManager:
    def __init__(self, gui):
        self.gui = gui
        self.data_folder = config.DATA_FOLDER
        self.device_names_file = config.DEVICE_NAMES_FILE
        self.devices_file = config.DATA_FILE
        self.device_names = self.load_device_names()
        self.devices = self.load_devices()

    def load_device_names(self):
        if os.path.exists(self.device_names_file):
            with open(self.device_names_file, "r") as file:
                data = json.load(file)
                if isinstance(data, dict):
                    logging.info("Device names loaded successfully")
                    return data
                else:
                    logging.warning("Device names file is not a dictionary")
                    return {}
        logging.warning("Device names file does not exist")
        return {}

    def save_device_names(self):
        os.makedirs(self.data_folder, exist_ok=True)
        with open(self.device_names_file, "w") as file:
            json.dump(self.device_names, file)
        logging.info("Device names saved successfully")

    def load_devices(self):
        if os.path.exists(self.devices_file):
            with open(self.devices_file, "r") as file:
                logging.info("Devices loaded successfully")
                return json.load(file)
        logging.warning("Devices file does not exist")
        return []

    def save_devices(self):
        os.makedirs(self.data_folder, exist_ok=True)
        with open(self.devices_file, "w") as file:
            json.dump(self.devices, file, indent=4)
        logging.info("Devices saved successfully")

    def on_device_select(self, event):
        selected_item = self.gui.device_tree.selection()
        if selected_item:
            device = self.gui.device_tree.item(selected_item[0], "values")
            ip, mac, vendor, OS, device_name, vulnerabilities = device
            self.gui.vulnerability_text.delete('1.0', tk.END)
            self.gui.vulnerability_text.insert(
                tk.END, f"Vulnerabilities for device {ip} (Vendor: {vendor}):\n{'=' * 80}\n")
            self.display_vulnerabilities(eval(vulnerabilities), ip, vendor)

    def display_vulnerabilities(self, vulnerabilities, ip, vendor):
        if not vulnerabilities:
            self.gui.vulnerability_text.insert(
                tk.END, f"No vulnerabilities found for the device {ip} (Vendor: {vendor})\n")
            return
        for vuln in vulnerabilities:
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', 'Unknown ID')
            description = cve.get('descriptions', [{}])[0].get(
                'value', 'No description available')
            severity = cve.get('metrics', {}).get('cvssMetricV2', [{}])[
                0].get('baseSeverity', 'Unknown')
            published_date = cve.get('published', 'Unknown')
            try:
                published_date = datetime.strptime(
                    published_date, '%Y-%m-%dT%H:%M:%S.%f').strftime('%Y-%m-%d %H:%M')
            except ValueError:
                pass
            resolved = 'Yes' if cve.get(
                'lastModified', '') != published_date else 'No'
            self.gui.vulnerability_text.insert(
                tk.END, f"CVE ID: {cve_id}\nDescription: {description}\nSeverity: {severity}\nPublished Date: {published_date}\nResolved: {resolved}\n{'-' * 80}\n")

    def process_device(self, device):
        vendor, OS, mac = device['vendor'], device['OS'], device['mac']
        device_name = self.device_names.get(
            mac, device.get('device_name', 'unknown'))
        if vendor == "Unknown":
            self.gui.device_tree.insert("", tk.END, values=(
                device['ip'], mac, vendor, OS, device_name, "[]"))
        else:
            vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(OS, vendor, device_name) if device_name.lower(
            ) != "unknown" else self.gui.vulnerability_checker.search_vulnerabilities(OS, self.gui.vulnerability_checker.extract_keyword(vendor))
            self.gui.device_tree.insert("", tk.END, values=(
                device['ip'], mac, vendor, OS, device_name, str(vulnerabilities)))
        relevant_info = device_name if device_name.lower() != "unknown" else (
            OS if OS.lower() != "unknown" else vendor)
        if relevant_info.lower() != "unknown" and relevant_info not in self.devices:
            self.devices.append(relevant_info)
            self.save_devices()
        logging.info("Processed device: %s", device)

    def search_vulnerabilities(self, user_input):
        if not user_input:
            logging.warning("No user input provided for vulnerability search")
            return
        self.gui.vulnerability_text.delete('1.0', tk.END)
        self.gui.vulnerability_text.insert(
            tk.END, f"Searching vulnerabilities for: {user_input}\n{'=' * 80}\n")
        vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(
            user_input, "Unknown")
        self.display_vulnerabilities(vulnerabilities, "N/A", user_input)
        logging.info("Searched vulnerabilities for: %s", user_input)

    def on_double_click(self, event):
        item = self.gui.device_tree.selection()[0]
        column = self.gui.device_tree.identify_column(event.x)
        if column == '#5':
            x, y, width, height = self.gui.device_tree.bbox(item, column)
            entry = ttk.Entry(self.gui.device_tree)
            entry.place(x=x, y=y, width=width, height=height)
            entry.focus()

            def save_edit(event):
                new_value = entry.get()
                self.gui.device_tree.set(item, column, new_value)
                entry.destroy()
                mac = self.gui.device_tree.item(item, "values")[1]
                self.device_names[mac] = new_value
                self.save_device_names()
                self.gui.vulnerability_text.delete('1.0', tk.END)
                vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(
                    new_value, "Unknown")
                self.gui.device_tree.set(item, '#6', str(vulnerabilities))
                self.display_vulnerabilities(vulnerabilities, "N/A", new_value)
                logging.info("Edited device name for MAC %s: %s", mac, new_value)

            entry.bind("<Return>", save_edit)
            entry.bind("<FocusOut>", lambda e: entry.destroy())
