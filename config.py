import os
import json

# allow overriding via environment for containerized runs
DATA_FOLDER = os.environ.get('DATA_FOLDER', 'user_data')
os.makedirs(DATA_FOLDER, exist_ok=True)

DATA_FILE = os.path.join(DATA_FOLDER, os.environ.get('DATA_FILE', 'notification_list.json'))
LOG_FILE = os.path.join(DATA_FOLDER, os.environ.get('LOG_FILE', 'security_scanner.log'))
HISTORY_FILE = os.path.join(DATA_FOLDER, os.environ.get('HISTORY_FILE', 'notification_history.json'))
DEVICE_INFO_FILE = os.path.join(DATA_FOLDER, os.environ.get('DEVICE_INFO_FILE', "device_info.json"))
NMAP_PATH = [os.environ.get('NMAP_PATH', '/usr/bin/nmap')]

# NETWORK_INTERFACES can be a JSON list string or single name
_net_if = os.environ.get('NETWORK_INTERFACES', None)
if _net_if:
    try:
        NETWORK_INTERFACES = json.loads(_net_if) if _net_if.strip().startswith('[') else [_net_if]
    except Exception:
        NETWORK_INTERFACES = [_net_if]
else:
    NETWORK_INTERFACES = None

API_KEY = os.environ.get('API_KEY', 'abcdefgh-abcd-abcd-abcd-abcdefghijkl')
