# Network Scanner and Vulnerability Checker


## Overview


The Network Scanner and Vulnerability Checker is a multi-mode tool designed to scan network devices, identify their vulnerabilities, and notify users about potential security risks. It integrates network scanning, vulnerability checking, and notification systems into a single, user-friendly interface.


## Features


- **Network Scanning**: Scan your network to discover connected devices and gather information such as IP address, MAC address, vendor, and model.
- **Vulnerability Checking**: Search for known vulnerabilities associated with the discovered devices using the National Vulnerability Database (NVD).
- **Notification System**: Get notified about new vulnerabilities found in your devices and maintain a history of notifications.
- **Results Exporting**: Export scan results and vulnerability details to a text file for further analysis.


## Installation


### Prerequisites


- Python 3.8 or higher
- `pip` (Python package installer)


### Clone the Repository


```bash
git clone https://github.com/mckwk/SecurityScanner.git
cd network-scanner-vulnerability-checker
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
NMAP_PATH = [r"C:\Nmap\nmap.exe"] # Your path goes here
```


## Usage


### Running the Application


```bash
python main.py
```


### User Interface


- **Mode Selection**: Choose between "Network Scan", "Search by Input", and "Notification System".
- **Network Scan**: Start scanning your network to discover devices and see related vulnerabilities.
- **Search by Input**: Manually search for vulnerabilities by entering device/system/program information.
- **Notification System**: Manage devices for which you want to receive vulnerability notifications.


### Exporting Results


- Click on the "Export Results" button to save the scan results and vulnerability details to a text file.


## Project Structure


- **UI/**: Contains the user interface components.
  - `gui.py`: Main GUI setup and event handling.
  - `progress_window.py`: Progress window for long-running tasks.
  - `notification_widgets.py`: Widgets for the notification system.
  - `notification_history_window.py`: Window to display notification history.
- **vulnerability_utils/**: Contains utilities for vulnerability checking.
  - [`vulnerability_checker.py`](command:_github.copilot.openRelativePath?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2Fgit%2FSecurityScanner%2Fvulnerability_utils%2Fvulnerability_checker.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%5D "d:\git\SecurityScanner\vulnerability_utils\vulnerability_checker.py"): Class to check vulnerabilities using NVD.
  - `vulnerability_detail_window.py`: Window to display detailed vulnerability information.
- **log_and_file_managers/**: Manages logging and file operations.
  - `logger_manager.py`: Logger setup and management.
  - `data_manager.py`: Handles saving and loading data to/from JSON files.
  - `results_exporter.py`: Exports scan results to a text file.
- **notification_utils/**: Manages notifications.
  - `notification_manager.py`: Handles sending notifications and managing notification history.
- [`network_scanner.py`](command:_github.copilot.openRelativePath?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2Fgit%2FSecurityScanner%2Fnetwork_scanner.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%5D "d:\git\SecurityScanner\network_scanner.py"): Scans the network to discover devices.
- [`device_manager.py`](command:_github.copilot.openRelativePath?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2Fgit%2FSecurityScanner%2Fdevice_manager.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%5D "d:\git\SecurityScanner\device_manager.py"): Manages device information and processes scan results.
- [`config.py`](command:_github.copilot.openRelativePath?%5B%7B%22scheme%22%3A%22file%22%2C%22authority%22%3A%22%22%2C%22path%22%3A%22%2Fd%3A%2Fgit%2FSecurityScanner%2Fconfig.py%22%2C%22query%22%3A%22%22%2C%22fragment%22%3A%22%22%7D%5D "d:\git\SecurityScanner\config.py"): Configuration file for paths and settings.


## Acknowledgements


- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [Tkinter](https://docs.python.org/3/library/tkinter.html) for the GUI
- [Spacy](https://spacy.io/) for natural language processing
- [Plyer](https://plyer.readthedocs.io/en/latest/) for desktop notifications


---
