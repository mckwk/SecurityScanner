import os

DATA_FOLDER = 'user_data'
DATA_FILE = os.path.join(DATA_FOLDER, 'notification_list.json')
LOG_FILE = os.path.join(DATA_FOLDER, 'notification_manager.log')
HISTORY_FILE = os.path.join(DATA_FOLDER, 'notification_history.json')
DEVICE_INFO_FILE = os.path.join(DATA_FOLDER, "device_info.json")
NMAP_PATH = [r"D:\Nmap\nmap.exe"]
# NMAP_PATH = [r"/usr/bin/nmap"]

# Optional parameter
# check the interfaces' names by running the following command in the terminal: python check_interface.py
# and replace the value of NETWORK_INTERFACES with the interface name(s) you want to use,
# e.g. for Windows: "{12345678-1234-1234-1234-1234567890ab}"
# e.g. for Linux: "enp0s3"
NETWORK_INTERFACES = ["{12345678-1234-1234-1234-1234567890ab}"]
