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

## Acknowledgements


- [National Vulnerability Database (NVD)](https://nvd.nist.gov/)
- [Tkinter](https://docs.python.org/3/library/tkinter.html) for the GUI
- [Spacy](https://spacy.io/) for natural language processing
- [Plyer](https://plyer.readthedocs.io/en/latest/) for desktop notifications


---
