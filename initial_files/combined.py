import tkinter as tk
from tkinter import ttk, scrolledtext
import requests
import nmap
from mac_vendor_lookup import MacLookup
from yeelight import Bulb, discover_bulbs
import re
import spacy
import threading

# Load the spaCy model
nlp = spacy.load("en_core_web_sm")

def extract_keyword(vendor_name):
    # Remove common suffixes
    suffixes = ['Inc.', 'Ltd.', 'Co.', 'Corporation', 'LLC', 'SA', 'GmbH', 'AG', 'S.A.', 'Pvt.', 'PLC', 'Limited']
    pattern = re.compile(r'\b(?:' + '|'.join(suffixes) + r')\b', re.IGNORECASE)
    vendor_name = pattern.sub('', vendor_name).strip()

    # Remove any remaining punctuation
    vendor_name = re.sub(r'[^\w\s]', '', vendor_name)

    # Use spaCy to process the vendor name
    doc = nlp(vendor_name)

    # Extract the most relevant keyword (proper noun or noun)
    keywords = [chunk.text.lower() for chunk in doc.noun_chunks if chunk.root.pos_ in ['PROPN', 'NOUN']]
    
    # Known brand names to prioritize
    known_brands = ['xiaomi', 'apple', 'microsoft', 'samsung', 'huawei', 'lenovo', 'dell', 'hp', 'asus', 'acer']

    # Check if any known brand is in the keywords
    for keyword in keywords:
        for brand in known_brands:
            if brand in keyword:
                return brand

    # Return the first keyword if available, otherwise return the cleaned vendor name
    return keywords[0] if keywords else vendor_name.split()[0].lower()

# Example usage
vendors = [
    "XIAOMI Electronics,CO.,LTD",
    "Cyfrowy Polsat SA",
    "Apple Inc.",
    "Microsoft Corporation",
    "Samsung Electronics Co., Ltd.",
    "Beijing Xiaomi Mobile Software Co Ltd"
]

for vendor in vendors:
    keyword = extract_keyword(vendor)
    print(f"Vendor: {vendor}, Keyword: {keyword}")

nmap_path = [r"C:\Nmap\nmap.exe"]

def scan_network():
    target_ip = "192.168.5.0/24"
    nm = nmap.PortScanner(nmap_search_path=nmap_path)
    nm.scan(hosts=target_ip, arguments='-sn')
    devices = []
    mac_lookup = MacLookup()
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            device_info = {
                'ip': nm[host]['addresses']['ipv4'],
                'mac': nm[host]['addresses']['mac'],
                'vendor': "Unknown",
                'model': "Unknown",
                'product_model': "Unknown"
            }
            try:
                device_info['vendor'] = mac_lookup.lookup(device_info['mac'])
            except:
                pass
            devices.append(device_info)
    return devices

def search_vulnerabilities(keyword, max_results=10):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        'keywordSearch': keyword,
        'resultsPerPage': max_results
    }
    if ' ' in keyword:
        params['keywordExactMatch'] = ''
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36'
    }
    response = requests.get(base_url, params=params, headers=headers)
    if response.status_code == 200:
        vulnerabilities = response.json().get('vulnerabilities', [])
        # Sort vulnerabilities by the latest first
        vulnerabilities.sort(key=lambda x: x.get('cve', {}).get('published', ''), reverse=True)
        return vulnerabilities
    else:
        return []

def display_vulnerabilities(vulnerabilities, text_widget, ip, vendor):
    text_widget.insert(tk.END, f"\nVulnerabilities for device {ip} (Vendor: {vendor}):\n")
    text_widget.insert(tk.END, "=" * 80 + "\n")
    if not vulnerabilities:
        text_widget.insert(tk.END, f"No vulnerabilities found for the device {ip} (Vendor: {vendor})\n")
        return
    for vuln in vulnerabilities:
        cve_id = vuln.get('cve', {}).get('id')
        descriptions = vuln.get('cve', {}).get('descriptions', [])
        description = descriptions[0].get('value') if descriptions else "No description available"
        severity = vuln.get('cve', {}).get('metrics', {}).get('cvssMetricV2', [{}])[0].get('baseSeverity', 'Unknown')
        text_widget.insert(tk.END, f"CVE ID: {cve_id}\n")
        text_widget.insert(tk.END, f"Description: {description}\n")
        text_widget.insert(tk.END, f"Severity: {severity}\n")
        text_widget.insert(tk.END, "-" * 80 + "\n")

def start_scan():
    # Create a new Toplevel window
    progress_window = tk.Toplevel(root)
    progress_window.title("Scan in Progress")
    progress_window.geometry("300x100")
    progress_window.resizable(False, False)
    
    # Center the popup window
    root.update_idletasks()
    x = (root.winfo_width() // 2) - (300 // 2)
    y = (root.winfo_height() // 2) - (100 // 2)
    progress_window.geometry(f"+{root.winfo_x() + x}+{root.winfo_y() + y}")
    
    # Add a label and a progress bar to the Toplevel window
    label = ttk.Label(progress_window, text="Scan in Progress...")
    label.pack(pady=10)
    
    progress_bar = ttk.Progressbar(progress_window, mode='indeterminate')
    progress_bar.pack(pady=10)
    progress_bar.start(interval=10)  # Set the interval to 10 milliseconds for faster movement
    
    scan_button.config(state=tk.DISABLED)
    device_list.delete('1.0', tk.END)
    vulnerability_text.delete('1.0', tk.END)
    
    def scan():
        devices = scan_network()
        for device in devices:
            if device['vendor'] == "Unknown":
                device_list.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}\n")
                continue
            keyword = extract_keyword(device['vendor'])
            device_list.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {keyword}\n")
            vulnerabilities = search_vulnerabilities(keyword)
            if not vulnerabilities and device['model'] != "Unknown":
                vulnerabilities = search_vulnerabilities(device['model'])
            display_vulnerabilities(vulnerabilities, vulnerability_text, device['ip'], keyword)
        progress_window.destroy()
        scan_button.config(state=tk.NORMAL)
    
    threading.Thread(target=scan).start()

# Setup the main window
root = tk.Tk()
root.title("Network Scanner and Vulnerability Checker")

# Apply a modern theme
style = ttk.Style()
style.theme_use('clam')

# Configure the grid to be scalable
root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
root.rowconfigure(1, weight=1)
root.rowconfigure(2, weight=0)

# Create a frame for the device list
device_frame = ttk.LabelFrame(root, text="Devices")
device_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
device_frame.columnconfigure(0, weight=1)
device_frame.rowconfigure(0, weight=1)

# Create a scrolled text widget for the device list
device_list = scrolledtext.ScrolledText(device_frame, width=80, height=20)
device_list.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

# Create a frame for the vulnerabilities
vulnerability_frame = ttk.LabelFrame(root, text="Vulnerabilities")
vulnerability_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
vulnerability_frame.columnconfigure(0, weight=1)
vulnerability_frame.rowconfigure(0, weight=1)

# Create a scrolled text widget for the vulnerabilities
vulnerability_text = scrolledtext.ScrolledText(vulnerability_frame, width=80, height=20)
vulnerability_text.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")

# Create a button to start the scan
scan_button = ttk.Button(root, text="Start Scan", command=start_scan)
scan_button.grid(row=2, column=0, padx=10, pady=10)

# Run the application
root.mainloop()