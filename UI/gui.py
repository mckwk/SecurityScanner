import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, ttk

from network_scanner import NetworkScanner

import config
from device_manager import DeviceManager
from log_and_file_managers.results_exporter import ResultsExporter
from notification_utils.notification_manager import NotificationManager
from UI.progress_window import ProgressWindow
from vulnerability_utils.vulnerability_checker import VulnerabilityChecker


class GUI:
    def __init__(self, root):
        self.root = root
        self._setup_root()
        self.device_manager = DeviceManager(self)
        self._setup_frames()
        self._setup_widgets()
        self.results_exporter = ResultsExporter(
            self.mode_combobox, self.device_tree, self.vulnerability_text)
        self.network_scanner = NetworkScanner(nmap_path=config.NMAP_PATH)
        self.vulnerability_checker = VulnerabilityChecker()
        self.notification_manager = NotificationManager(
            self.notification_frame)
        self.cancel_event = threading.Event()
        self.on_mode_change()

    def _setup_root(self):
        self.root.title("Network Scanner and Vulnerability Checker")
        self.root.geometry("800x600")
        for i in range(5):
            self.root.rowconfigure(i, weight=1 if i in [1, 2] else 0)
        self.root.columnconfigure(0, weight=1)

    def _setup_frames(self):
        self.device_frame = self._create_frame("Devices", 1)
        self.vulnerability_frame = self._create_frame("Vulnerabilities", 2)
        self.search_frame = self._create_frame("Search Vulnerabilities", 1)
        self.notification_frame = self._create_frame("Notification System", 1)

    def _create_frame(self, text, row):
        frame = ttk.LabelFrame(self.root, text=text)
        frame.grid(row=row, column=0, padx=10, pady=10, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        return frame

    def _setup_widgets(self):
        self.mode_combobox = self._create_combobox(
            ["Network Scan", "Search by Input", "Notification System"], 0)
        self.device_tree = self._create_treeview(
            self.device_frame, [
                "IP", "MAC", "Vendor", "OS", "Device Name", "Vulnerabilities"])
        self.vulnerability_text = self._create_scrolledtext(
            self.vulnerability_frame)
        self.scan_button = self._create_button("Start", self.start_action, 3)
        self.export_button = self._create_button(
            "Export Results", self.export_results, 4)
        self.search_entry = self._create_entry(self.search_frame, 0)
        self.search_button = self._create_button(
            "Search", self.search_by_input, 0, 1, self.search_frame)

    def _create_combobox(self, values, row):
        combobox = ttk.Combobox(self.root, values=values, state="readonly")
        combobox.current(0)
        combobox.grid(row=row, column=0, padx=10, pady=10, sticky="ew")
        combobox.bind("<<ComboboxSelected>>", self.on_mode_change)
        return combobox

    def _create_treeview(self, parent, columns):
        tree = ttk.Treeview(parent, columns=columns, show="headings")
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150 if col !=
                        "Vulnerabilities" else 0, stretch=tk.NO)
        tree.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        tree.bind("<<TreeviewSelect>>", self.device_manager.on_device_select)
        tree.bind("<Double-1>", self.device_manager.on_double_click)
        return tree

    def _create_scrolledtext(self, parent):
        text = scrolledtext.ScrolledText(parent, width=80, height=20)
        text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        return text

    def _create_button(self, text, command, row, column=0, parent=None):
        parent = parent or self.root
        button = ttk.Button(parent, text=text, command=command)
        button.grid(row=row, column=column, padx=10, pady=10)
        return button

    def _create_entry(self, parent, row):
        entry = ttk.Entry(parent, width=50)
        entry.grid(row=row, column=0, padx=10, pady=10, sticky="ew")
        entry.bind("<Return>", lambda event: self.search_by_input())
        return entry

    def on_mode_change(self, event=None):
        selected_mode = self.mode_combobox.get()
        self.vulnerability_text.delete('1.0', tk.END)
        self._toggle_frames(selected_mode)
        if selected_mode == "Notification System":
            self.notification_manager.load_notification_list_from_json()

    def _toggle_frames(self, mode):
        frames = {
            "Network Scan": [
                self.device_frame,
                self.vulnerability_frame,
                self.scan_button,
                self.export_button],
            "Search by Input": [
                self.vulnerability_frame,
                self.search_frame,
                self.scan_button,
                self.export_button],
            "Notification System": [
                self.notification_frame]}
        for frame in [
                self.device_frame,
                self.vulnerability_frame,
                self.search_frame,
                self.notification_frame,
                self.scan_button,
                self.export_button]:
            frame.grid_remove()
        for frame in frames.get(mode, []):
            frame.grid()

    def start_action(self):
        {"Network Scan": self.start_scan, "Search by Input": self.search_by_input}.get(
            self.mode_combobox.get(), lambda: None)()

    def start_scan(self):
        self._run_in_thread(
            self.network_scanner.scan_network,
            self.device_manager.process_device,
            self.scan_button)

    def search_by_input(self):
        self._run_in_thread(lambda: self.device_manager.search_vulnerabilities(
            self.search_entry.get()), None, self.search_button)

    def _run_in_thread(self, target, process, button):
        self.cancel_event.clear()
        progress_window = ProgressWindow(
            self.root, "In Progress", self.cancel_scan)
        button.config(state=tk.DISABLED)
        self.device_tree.delete(*self.device_tree.get_children())
        self.vulnerability_text.delete('1.0', tk.END)

        def task():
            result = target()
            if process:
                for item in result:
                    if self.cancel_event.is_set():
                        break
                    process(item)
            progress_window.destroy()
            button.config(state=tk.NORMAL)

        threading.Thread(target=task).start()

    def cancel_scan(self):
        self.cancel_event.set()

    def export_results(self):
        self.results_exporter.export_results()
