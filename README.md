# Network Scanner and Vulnerability Checker - API


## Overview


This is the API branch of the SecurityScanner project.



### Prerequisites


- All prerequisites from the main SecurityScanner branch
- Flask (```bash pip install flask```)


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

- **Search Vulnerabilities by Keywords**
```bash
curl -X POST http://127.0.0.1:5000/search_vulnerabilities -d "model=test_model&vendor=test_vendor&device_info=test_id"
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

## Project Structure


- **UI/**: Contains the user interface components.
  - `app.py`: API call handling.
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
