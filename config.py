import os

DATA_FOLDER = 'user_data'
DATA_FILE = os.path.join(DATA_FOLDER, 'notification_list.json')
LOG_FILE = os.path.join(DATA_FOLDER, 'security_scanner.log')
HISTORY_FILE = os.path.join(DATA_FOLDER, 'notification_history.json')
DEVICE_INFO_FILE = os.path.join(DATA_FOLDER, "device_info.json")
NMAP_PATH = [r"D:\Nmap\nmap.exe"] # NMAP_PATH = [r"/usr/bin/nmap"]

# Optional parameters
# check the interfaces' names by running the following command in the terminal: python check_interface.py
# and replace the value of NETWORK_INTERFACES with the interface name(s) you want to use,
# e.g. for Windows: "{12345678-1234-1234-1234-1234567890ab}"
# e.g. for Linux: "enp0s3"
NETWORK_INTERFACES = ["enp0s3"] 
# The public rate limit (without an API key) is 5 requests in a rolling 30 second window; 
# the rate limit with an API key is 50 requests in a rolling 30 second window. 
API_KEY = 'abcdefgh-abcd-abcd-abcd-abcdefghijkl'
