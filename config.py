import os

DATA_FOLDER = 'user_data'
DATA_FILE = os.path.join(DATA_FOLDER, 'notification_list.json')
LOG_FILE = os.path.join(DATA_FOLDER, 'notification_manager.log')
HISTORY_FILE = os.path.join(DATA_FOLDER, 'notification_history.json')
DEVICE_INFO_FILE = os.path.join(DATA_FOLDER, "device_info.json")
NMAP_PATH = [r"D:\Nmap\nmap.exe"]

# Optional parameter
# check the interfaces' names by running the following command in the terminal: python check_interface.py
# and replace the value of NETWORK_INTERFACES with the interface name(s) you want to use,
# e.g. for Windows: "{12345678-1234-1234-1234-1234567890ab}"
NETWORK_INTERFACES = ["{FBDEA24E-D69D-4408-A542-EC6530B39376}"]
