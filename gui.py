import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
from network_scanner import NetworkScanner
from vulnerability_checker import VulnerabilityChecker
from datetime import datetime
from device_manager import DeviceManager

class GUI:
    def __init__(self, root):
        self.root = root
        self._setup_root()
        self.device_manager = DeviceManager(self)
        self._setup_frames()
        self._setup_widgets()
        self.network_scanner = NetworkScanner(nmap_path=[r"C:\Nmap\nmap.exe"])
        self.vulnerability_checker = VulnerabilityChecker()

    def _setup_root(self):
        self.root.title("Network Scanner and Vulnerability Checker")
        self.root.set_theme('arc')
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        self.root.rowconfigure(2, weight=0)
        self.root.rowconfigure(3, weight=0)

    def _setup_frames(self):
        self.device_frame = ttk.LabelFrame(self.root, text="Devices")
        self.device_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.device_frame.columnconfigure(0, weight=1)
        self.device_frame.rowconfigure(0, weight=1)

        self.vulnerability_frame = ttk.LabelFrame(self.root, text="Vulnerabilities")
        self.vulnerability_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.vulnerability_frame.columnconfigure(0, weight=1)
        self.vulnerability_frame.rowconfigure(0, weight=1)

    def _setup_widgets(self):
        self.device_tree = ttk.Treeview(self.device_frame, columns=("IP", "MAC", "Vendor", "Model", "Product ID", "Vulnerabilities"), show="headings")
        self.device_tree.heading("IP", text="IP Address")
        self.device_tree.heading("MAC", text="MAC Address")
        self.device_tree.heading("Vendor", text="Vendor")
        self.device_tree.heading("Model", text="Model")
        self.device_tree.heading("Product ID", text="Product ID")
        self.device_tree.heading("Vulnerabilities", text="Vulnerabilities")
        self.device_tree.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.device_tree.bind("<<TreeviewSelect>>", self.device_manager.on_device_select)
        self.device_tree.bind("<Double-1>", self.device_manager.on_double_click)

        self.device_tree.column("IP", width=150)
        self.device_tree.column("MAC", width=150)
        self.device_tree.column("Vendor", width=150)
        self.device_tree.column("Model", width=150)
        self.device_tree.column("Product ID", width=150)
        self.device_tree.column("Vulnerabilities", width=0, stretch=tk.NO)

        self.vulnerability_text = scrolledtext.ScrolledText(self.vulnerability_frame, width=80, height=20)
        self.vulnerability_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

        self.scan_button = ttk.Button(self.root, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=2, column=0, padx=10, pady=10)

        self.search_frame = ttk.LabelFrame(self.root, text="Search Vulnerabilities")
        self.search_frame.grid(row=3, column=0, padx=10, pady=10, sticky="nsew")
        self.search_frame.columnconfigure(0, weight=1)
        self.search_frame.rowconfigure(0, weight=1)

        self.search_entry = ttk.Entry(self.search_frame, width=50)
        self.search_entry.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.search_button = ttk.Button(self.search_frame, text="Search", command=self.device_manager.search_vulnerabilities)
        self.search_button.grid(row=0, column=1, padx=10, pady=10)

    def start_scan(self):
        progress_window = self._create_progress_window()
        self.scan_button.config(state=tk.DISABLED)
        self.device_tree.delete(*self.device_tree.get_children())
        self.vulnerability_text.delete('1.0', tk.END)

        def scan():
            devices = self.network_scanner.scan_network("192.168.5.0/24")
            for device in devices:
                self.device_manager.process_device(device)
            progress_window.destroy()
            self.scan_button.config(state=tk.NORMAL)

        threading.Thread(target=scan).start()

    def _create_progress_window(self):
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