# config.py
import os

DATA_FOLDER = 'user_data'
DATA_FILE = os.path.join(DATA_FOLDER, 'devices.json')
LOG_FILE = os.path.join(DATA_FOLDER, 'notification_manager.log')
HISTORY_FILE = os.path.join(DATA_FOLDER, 'notification_history.json')
PRODUCT_IDS_FILE = os.path.join(DATA_FOLDER, "product_ids.json")
NMAP_PATH = [r"C:\Nmap\nmap.exe"]