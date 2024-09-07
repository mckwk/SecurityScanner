import tkinter as tk
from tkinter import ttk
from datetime import datetime
import json
import os
import config

class DeviceManager:
    def __init__(self, gui):
        self.gui = gui
        self.data_folder = config.DATA_FOLDER
        self.product_ids_file = config.PRODUCT_IDS_FILE
        self.devices_file = config.DATA_FILE
        self.product_ids = self.load_product_ids()
        self.devices = self.load_devices()

    def load_product_ids(self):
        if os.path.exists(self.product_ids_file):
            with open(self.product_ids_file, "r") as file:
                data = json.load(file)
                if isinstance(data, dict):
                    return data
                else:
                    return {}
        return {}

    def save_product_ids(self):
        os.makedirs(self.data_folder, exist_ok=True)
        with open(self.product_ids_file, "w") as file:
            json.dump(self.product_ids, file)

    def load_devices(self):
        if os.path.exists(self.devices_file):
            with open(self.devices_file, "r") as file:
                return json.load(file)
        return []

    def save_devices(self):
        os.makedirs(self.data_folder, exist_ok=True)
        with open(self.devices_file, "w") as file:
            json.dump(self.devices, file, indent=4)

    def on_device_select(self, event):
        selected_item = self.gui.device_tree.selection()
        if selected_item:
            device = self.gui.device_tree.item(selected_item[0], "values")
            ip, mac, vendor, model, product_id, vulnerabilities = device
            self.gui.vulnerability_text.delete('1.0', tk.END)
            self.gui.vulnerability_text.insert(tk.END, f"Vulnerabilities for device {ip} (Vendor: {vendor}):\n{'=' * 80}\n")
            self.display_vulnerabilities(eval(vulnerabilities), ip, vendor)

    def display_vulnerabilities(self, vulnerabilities, ip, vendor):
        if not vulnerabilities:
            self.gui.vulnerability_text.insert(tk.END, f"No vulnerabilities found for the device {ip} (Vendor: {vendor})\n")
            return
        for vuln in vulnerabilities:
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', 'Unknown ID')
            description = cve.get('descriptions', [{}])[0].get('value', 'No description available')
            severity = cve.get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity', 'Unknown')
            published_date = cve.get('published', 'Unknown')
            try:
                published_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%M:%S.%f').strftime('%Y-%m-%d %H:%M')
            except ValueError:
                pass
            resolved = 'Yes' if cve.get('lastModified', '') != published_date else 'No'
            self.gui.vulnerability_text.insert(tk.END, f"CVE ID: {cve_id}\nDescription: {description}\nSeverity: {severity}\nPublished Date: {published_date}\nResolved: {resolved}\n{'-' * 80}\n")

    def process_device(self, device):
        vendor, model, mac = device['vendor'], device['model'], device['mac']
        product_id = self.product_ids.get(mac, device.get('product_id', 'unknown'))
        if vendor == "Unknown":
            self.gui.device_tree.insert("", tk.END, values=(device['ip'], mac, vendor, model, product_id, "[]"))
        else:
            vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(model, vendor, product_id) if product_id.lower() != "unknown" else self.gui.vulnerability_checker.search_vulnerabilities(model, self.gui.vulnerability_checker.extract_keyword(vendor))
            self.gui.device_tree.insert("", tk.END, values=(device['ip'], mac, vendor, model, product_id, str(vulnerabilities)))
        relevant_info = product_id if product_id.lower() != "unknown" else (model if model.lower() != "unknown" else vendor)
        if relevant_info.lower() != "unknown" and relevant_info not in self.devices:
            self.devices.append(relevant_info)
            self.save_devices()

    def search_vulnerabilities(self, user_input):
        if not user_input:
            return
        self.gui.vulnerability_text.delete('1.0', tk.END)
        self.gui.vulnerability_text.insert(tk.END, f"Searching vulnerabilities for: {user_input}\n{'=' * 80}\n")
        vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(user_input, "Unknown")
        self.display_vulnerabilities(vulnerabilities, "N/A", user_input)

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
                self.product_ids[mac] = new_value
                self.save_product_ids()
                self.gui.vulnerability_text.delete('1.0', tk.END)
                vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(new_value, "Unknown")
                self.gui.device_tree.set(item, '#6', str(vulnerabilities))
                self.display_vulnerabilities(vulnerabilities, "N/A", new_value)

            entry.bind("<Return>", save_edit)
            entry.bind("<FocusOut>", lambda e: entry.destroy())