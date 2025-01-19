# Network Scanner and Vulnerability Checker - API


## Overview


This is the API branch of the SecurityScanner project.



## Installation


### Prerequisites


- Python 3.8 or higher
- `pip` (Python package installer)
- [Visual C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/)


### Clone the Repository


```bash
git clone --branch api https://github.com/mckwk/SecurityScanner.git
cd SecurityScanner
```


### Install Dependencies


```bash
pip install -r requirements.txt
```


### Configuration


Modify [`config.py`](command:_github.copilot.openRelativePath?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2Fgit%2FSecurityScanner%2Fconfig.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%5D "d:\git\SecurityScanner\config.py") file in the root directory with:
- **NMAP_PATH**: your nmap executable path
- **NETWORK_INTERFACES**: name or a list of names of interfaces that you want to use for the scan (optional)
- **API_KEY**: your NVD API key (optional)

```python
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

```


## Usage


### Running the Application

If used on a Linux-based system, make sure you execute the file with root privileges.

- **GUI mode**
```bash
python main.py
```

- **API**
```bash
python api.py
```


### Example API calls using CURL


- **Network Scan**
Specifying network address is optional.
```bash
curl -X GET http://127.0.0.1:5000/network_scan
curl -X GET "http://127.0.0.1:5000/network_scan?network=192.168.0.0/24"
```

- **Full Network Scan** 
This scan gives more device info than the regular scan, but also takes longer to run. Specifying network address is optional.
```bash
curl -X GET http://127.0.0.1:5000/full_network_scan
curl -X GET "http://127.0.0.1:5000/full_network_scan?network=192.168.0.0/24"
```

- **Network Scan and Vulnerability Search**
Specifying network address is optional.
```bash
curl -X GET http://127.0.0.1:5000/scan_and_search_vulnerabilities
curl -X GET "http://127.0.0.1:5000/scan_and_search_vulnerabilities?network=192.168.0.0/24"
```

- **Scan Vulnerabilities for a Single IP**
```bash
curl -X POST "http://127.0.0.1:5000/scan_vulnerabilities?ip=192.168.0.0"
```

- **Search Vulnerabilities by Keywords**
Not all keywords have to be specified.
```bash
curl -X POST http://127.0.0.1:5000/search_vulnerabilities -d "vendor=test_model&os=test_vendor&device_info=test_id"
```

- **Get Notification History**
```bash
curl -X GET http://127.0.0.1:5000/notification_history
```

Returned values are in JSON format.



## Acknowledgements


- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [Tkinter](https://docs.python.org/3/library/tkinter.html) for the GUI
- [Spacy](https://spacy.io/) for natural language processing
- [Plyer](https://plyer.readthedocs.io/en/latest/) for desktop notifications


---
