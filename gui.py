import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from network_scanner import NetworkScanner
from vulnerability_checker import VulnerabilityChecker

class GUI:
    def __init__(self, root):
        """
        Initialize the GUI with the root window.
        
        Args:
            root (tk.Tk): The root window.
        """
        self.root = root
        self._setup_root()
        self._setup_frames()
        self._setup_widgets()
        self.network_scanner = NetworkScanner(nmap_path=[r"C:\Nmap\nmap.exe"])
        self.vulnerability_checker = VulnerabilityChecker()

    def _setup_root(self):
        """Setup the root window configuration."""
        self.root.title("Network Scanner and Vulnerability Checker")
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=0)

    def _setup_frames(self):
        """Setup the frames for devices and vulnerabilities."""
        self.device_frame = ttk.LabelFrame(self.root, text="Devices")
        self.device_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.device_frame.columnconfigure(0, weight=1)
        self.device_frame.rowconfigure(0, weight=1)

        self.vulnerability_frame = ttk.LabelFrame(self.root, text="Vulnerabilities")
        self.vulnerability_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.vulnerability_frame.columnconfigure(0, weight=1)
        self.vulnerability_frame.rowconfigure(0, weight=1)

    def _setup_widgets(self):
        """Setup the widgets for displaying devices and vulnerabilities."""
        self.device_list = scrolledtext.ScrolledText(self.device_frame, width=80, height=20)
        self.device_list.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.vulnerability_text = scrolledtext.ScrolledText(self.vulnerability_frame, width=80, height=20)
        self.vulnerability_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.scan_button = ttk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=2, column=0, padx=10, pady=10)

    def display_vulnerabilities(self, vulnerabilities, ip, vendor):
        """
        Display vulnerabilities for a given device.
        
        Args:
            vulnerabilities (list): List of vulnerabilities.
            ip (str): IP address of the device.
            vendor (str): Vendor of the device.
        """
        self.vulnerability_text.insert(tk.END, f"\nVulnerabilities for device {ip} (Vendor: {vendor}):\n")
        self.vulnerability_text.insert(tk.END, "=" * 80 + "\n")
        if not vulnerabilities:
            self.vulnerability_text.insert(tk.END, f"No vulnerabilities found for the device {ip} (Vendor: {vendor})\n")
            return
        for vuln in vulnerabilities:
            cve_id = vuln.get('cve', {}).get('id')
            descriptions = vuln.get('cve', {}).get('descriptions', [])
            description = descriptions[0].get('value') if descriptions else "No description available"
            severity = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity', 'Unknown')
            self.vulnerability_text.insert(tk.END, f"CVE ID: {cve_id}\n")
            self.vulnerability_text.insert(tk.END, f"Description: {description}\n")
            self.vulnerability_text.insert(tk.END, f"Severity: {severity}\n")
            self.vulnerability_text.insert(tk.END, "-" * 80 + "\n")

    def start_scan(self):
        """Start the network scan in a separate thread."""
        progress_window = self._create_progress_window()
        self.scan_button.config(state=tk.DISABLED)
        self.device_list.delete('1.0', tk.END)
        self.vulnerability_text.delete('1.0', tk.END)

        def scan():
            devices = self.network_scanner.scan_network("192.168.5.0/24")
            for device in devices:
                self._process_device(device)
            progress_window.destroy()
            self.scan_button.config(state=tk.NORMAL)

        threading.Thread(target=scan).start()

    def _create_progress_window(self):
        """Create a progress window to show scan progress."""
        progress_window = tk.Toplevel(self.root)
        progress_window.title("Scan in Progress")
        progress_window.geometry("300x100")
        progress_window.resizable(False, False)
        self.root.update_idletasks()
        x = (self.root.winfo_width() // 2) - (300 // 2)
        y = (self.root.winfo_height() // 2) - (100 // 2)
        progress_window.geometry(f"+{self.root.winfo_x() + x}+{self.root.winfo_y() + y}")
        label = ttk.Label(progress_window, text="Scan in Progress...")
        label.pack(pady=10)
        progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
        progress_bar.pack(pady=10)
        progress_bar.start(interval=10)
        return progress_window

    def _process_device(self, device):
        """Process each device found during the scan."""
        if device['vendor'] == "Unknown":
            self.device_list.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}\n")
            return
        keyword = self.vulnerability_checker.extract_keyword(device['vendor'])
        self.device_list.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {keyword}\n")
        vulnerabilities = self.vulnerability_checker.search_vulnerabilities(keyword)
        if not vulnerabilities and device['model'] != "Unknown":
            vulnerabilities = self.vulnerability_checker.search_vulnerabilities(device['model'])
        self.display_vulnerabilities(vulnerabilities, device['ip'], keyword)