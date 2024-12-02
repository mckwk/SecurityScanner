from flask import Flask, jsonify, request

import config
from log_and_file_managers.data_manager import DataManager
from network_scanner import NetworkScanner
from notification_utils.notification_manager import NotificationManager
from vulnerability_utils.vulnerability_checker import VulnerabilityChecker

app = Flask(__name__)

network_scanner = NetworkScanner(nmap_path=config.NMAP_PATH)
vulnerability_checker = VulnerabilityChecker()
data_manager = DataManager(
    config.DATA_FOLDER,
    config.DATA_FILE,
    config.HISTORY_FILE,
    None)


@app.route('/scan_network', methods=['GET'])
def scan_network():
    devices = network_scanner.scan_network()
    return jsonify(devices)


@app.route('/search_vulnerabilities', methods=['POST'])
def search_vulnerabilities():
    vendor = request.form.get('vendor')
    os = request.form.get('os')
    device_info = request.form.get('device_info')
    vulnerabilities = vulnerability_checker.search_vulnerabilities(
        vendor, os, device_info)
    return jsonify(vulnerabilities)


@app.route('/notification_history', methods=['GET'])
def notification_history():
    history = data_manager.load_notification_history()
    return jsonify(history)


@app.route('/scan_vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    ip = request.form.get('ip')
    device_info = network_scanner._scan_single_ip(ip)
    vulnerabilities = vulnerability_checker.search_vulnerabilities(
        device_info['OS'], device_info['vendor'], device_info['device_name'])
    return jsonify(vulnerabilities)


@app.route('/scan_and_search_vulnerabilities', methods=['GET'])
def scan_and_search_vulnerabilities():
    devices = network_scanner.scan_network()
    for device in devices:
        vulnerabilities = vulnerability_checker.search_vulnerabilities(
            device['OS'], device['vendor'], device['device_name'])
        device['vulnerabilities'] = vulnerabilities
    return jsonify(devices)


if __name__ == '__main__':
    app.run(debug=True)