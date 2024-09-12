import tkinter as tk
from tkinter import filedialog


class ResultsExporter:
    def __init__(self, mode_combobox, device_tree, vulnerability_text):
        self.mode_combobox = mode_combobox
        self.device_tree = device_tree
        self.vulnerability_text = vulnerability_text

    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[
                                                 ("Text files", "*.txt"), ("All files", "*.*")])
        if not file_path:
            return

        with open(file_path, 'w', encoding='utf-8') as file:
            selected_mode = self.mode_combobox.get()
            if selected_mode == "Network Scan":
                self._export_network_scan_results(file)
            elif selected_mode == "Search by Input":
                self._export_search_results(file)

    def _export_network_scan_results(self, file):
        for child in self.device_tree.get_children():
            device = self.device_tree.item(child, "values")
            file.write(f"IP Address: {device[0]}\n")
            file.write(f"MAC Address: {device[1]}\n")
            file.write(f"Vendor: {device[2]}\n")
            file.write(f"Model: {device[3]}\n")
            file.write(f"Product ID: {device[4]}\n")
            file.write("Vulnerabilities:\n")
            vulnerabilities = eval(device[5])
            for vuln in vulnerabilities:
                cve = vuln.get('cve', {})
                file.write(f"CVE ID: {cve.get('id', 'N/A')}\n")
                description = cve.get('descriptions', [{}])[
                    0].get('value', 'N/A')
                file.write(f"Description: {description}\n")
                severity = cve.get('metrics', {}).get('cvssMetricV2', [{}])[
                    0].get('cvssData', {}).get('baseSeverity', 'N/A')
                file.write(f"Severity: {severity}\n")
                published_date = cve.get('published', 'N/A')
                file.write(f"Published Date: {published_date}\n")
                resolved = 'Yes' if cve.get(
                    'vulnStatus', 'N/A') == 'Analyzed' else 'No'
                file.write(f"Resolved: {resolved}\n")
                file.write("-" * 80 + "\n")
            file.write("=" * 80 + "\n\n")

    def _export_search_results(self, file):
        vulnerabilities_content = self.vulnerability_text.get('1.0', tk.END)
        file.write("Vulnerabilities:\n")
        file.write(vulnerabilities_content)
