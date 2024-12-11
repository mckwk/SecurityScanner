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


Modify [`config.py`](command:_github.copilot.openRelativePath?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2Fgit%2FSecurityScanner%2Fconfig.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%5D "d:\git\SecurityScanner\config.py") file in the root directory with your nmap executable path:


```python
DATA_FOLDER = 'user_data'
DATA_FILE = os.path.join(DATA_FOLDER, 'devices.json')
LOG_FILE = os.path.join(DATA_FOLDER, 'notification_manager.log')
HISTORY_FILE = os.path.join(DATA_FOLDER, 'notification_history.json')
PRODUCT_IDS_FILE = os.path.join(DATA_FOLDER, "product_ids.json")
NMAP_PATH = [r"D:\Nmap\nmap.exe"] # Your path goes here
```


## Usage


### Running the Application

- **GUI mode**
```bash
python main.py
```

- **API**
```bash
python app.py
```


### Example API calls using CURL


- **Scan Network**
```bash
curl -X GET http://127.0.0.1:5000/scan_network
```

- **Full Network Scan** 
This scan gives more device info than the regular scan, but also takes longer to run.
```bash
curl -X GET http://127.0.0.1:5000/full_network_scan
```

- **Search Vulnerabilities by Keywords**
Not all keywords have to be specified.
```bash
curl -X POST http://127.0.0.1:5000/search_vulnerabilities -d "vendor=test_model&os=test_vendor&device_info=test_id"
```

- **Scan Network and Search Vulnerabilities**
```bash
curl -X GET http://127.0.0.1:5000/scan_and_search_vulnerabilities
```

- **Get Notification History**
```bash
curl -X GET http://127.0.0.1:5000/notification_history
```

- **Scan Vulnerabilities for a Single IP**
```bash
curl -X POST http://127.0.0.1:5000/scan_vulnerabilities -d "ip=192.168.1.1"
```
Returned values are in JSON format.



## Acknowledgements


- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [Tkinter](https://docs.python.org/3/library/tkinter.html) for the GUI
- [Spacy](https://spacy.io/) for natural language processing
- [Plyer](https://plyer.readthedocs.io/en/latest/) for desktop notifications


---
