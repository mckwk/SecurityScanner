import tkinter as tk
from tkinter import ttk
from datetime import datetime

class DeviceManager:
    def __init__(self, gui):
        self.gui = gui

    def on_device_select(self, event):
        selected_item = self.gui.device_tree.selection()
        if selected_item:
            device = self.gui.device_tree.item(selected_item[0], "values")
            ip, mac, vendor, model, product_id, vulnerabilities = device
            self.gui.vulnerability_text.delete('1.0', tk.END)
            self.gui.vulnerability_text.insert(tk.END, f"Vulnerabilities for device {ip} (Vendor: {vendor}):\n")
            self.gui.vulnerability_text.insert(tk.END, "=" * 80 + "\n")
            self.display_vulnerabilities(eval(vulnerabilities), ip, vendor)

    def display_vulnerabilities(self, vulnerabilities, ip, vendor):
        if not vulnerabilities:
            self.gui.vulnerability_text.insert(tk.END, f"No vulnerabilities found for the device {ip} (Vendor: {vendor})\n")
            return
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve', {}).get('id')
            descriptions = vuln.get('cve', {}).get('descriptions', [])
            description = descriptions[0].get('value') if descriptions else "No description available"
            severity = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity', 'Unknown')
            published_date = vuln.get('cve', {}).get('published', 'Unknown')
            try:
                published_date = datetime.strptime(published_date, '%Y-%m-%dT%H:%M:%S.%f').strftime('%Y-%m-%d %H:%M')
            except ValueError:
                pass
            resolved = 'Yes' if vuln.get('cve', {}).get('lastModified', '') != published_date else 'No'
            self.gui.vulnerability_text.insert(tk.END, f"CVE ID: {cve_id}\n")
            self.gui.vulnerability_text.insert(tk.END, f"Description: {description}\n")
            self.gui.vulnerability_text.insert(tk.END, f"Severity: {severity}\n")
            self.gui.vulnerability_text.insert(tk.END, f"Published Date: {published_date}\n")
            self.gui.vulnerability_text.insert(tk.END, f"Resolved: {resolved}\n")
            self.gui.vulnerability_text.insert(tk.END, "-" * 80 + "\n")

    def process_device(self, device):
        vendor = device['vendor']
        model = device['model']
        if vendor == "Unknown":
            self.gui.device_tree.insert("", tk.END, values=(device['ip'], device['mac'], vendor, model, device['product_id'], "[]"))
            return
        keyword = self.gui.vulnerability_checker.extract_keyword(vendor)
        vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(model, keyword)
        self.gui.device_tree.insert("", tk.END, values=(device['ip'], device['mac'], vendor, model, device['product_id'], str(vulnerabilities)))

    def search_vulnerabilities(self, user_input):
        if not user_input:
            return
        self.gui.vulnerability_text.delete('1.0', tk.END)
        self.gui.vulnerability_text.insert(tk.END, f"Searching vulnerabilities for: {user_input}\n")
        self.gui.vulnerability_text.insert(tk.END, "=" * 80 + "\n")
        # Assuming user_input is a model, and vendor is unknown in this context
        vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(user_input, "Unknown")
        self.display_vulnerabilities(vulnerabilities, "N/A", user_input)

    def on_double_click(self, event):
        item = self.gui.device_tree.selection()[0]
        column = self.gui.device_tree.identify_column(event.x)
        if column == '#5':  # Product ID column
            x, y, width, height = self.gui.device_tree.bbox(item, column)
            entry = ttk.Entry(self.gui.device_tree)
            entry.place(x=x, y=y, width=width, height=height)
            entry.focus()

            def save_edit(event):
                new_value = entry.get()
                self.gui.device_tree.set(item, column, new_value)
                entry.destroy()
                # Perform a new scan using the product ID
                self.gui.vulnerability_text.delete('1.0', tk.END)  # Clear the vulnerabilities subwindow
                vulnerabilities = self.gui.vulnerability_checker.search_vulnerabilities(new_value, "Unknown")
                self.gui.device_tree.set(item, '#6', str(vulnerabilities))
                self.display_vulnerabilities(vulnerabilities, "N/A", new_value)  # Refresh the vulnerabilities subwindow

            entry.bind("<Return>", save_edit)
            entry.bind("<FocusOut>", lambda e: entry.destroy())