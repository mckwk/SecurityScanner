from flask import Flask, jsonify, request
from network_utils.network_scanner import NetworkScanner

import config
from device_manager import DeviceManager
from log_and_file_managers.data_manager import DataManager
from notification_utils.notification_manager import NotificationManager
from vulnerability_utils.vulnerability_checker import VulnerabilityChecker

app = Flask(__name__)

network_scanner = NetworkScanner(nmap_path=config.NMAP_PATH)
vulnerability_checker = VulnerabilityChecker()
device_manager = DeviceManager(None)
data_manager = DataManager(
    config.DATA_FOLDER,
    config.DATA_FILE,
    config.HISTORY_FILE,
    config.DEVICE_INFO_FILE
)


@app.route('/full_network_scan', methods=['GET'])
def full_network_scan():
    network = request.args.get('network')
    devices = network_scanner.full_network_scan(network)
    return jsonify(devices)


@app.route('/network_scan', methods=['GET'])
def network_scan():
    network = request.args.get('network')
    devices = network_scanner.scan_network(network)
    for device in devices:
        device['vulnerabilities'] = []
    device_manager.device_info = devices
    device_manager.save_device_info()
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
    ip = request.args.get('ip')
    device_info = network_scanner._scan_single_ip(ip)
    vulnerabilities = vulnerability_checker.search_vulnerabilities(
        device_info['OS'], device_info['vendor'], device_info['device_name'])
    return jsonify(vulnerabilities)


@app.route('/scan_and_search_vulnerabilities', methods=['GET'])
def scan_and_search_vulnerabilities():
    network = request.args.get('network')
    devices = network_scanner.scan_network(network)
    for device in devices:
        vulnerabilities = vulnerability_checker.search_vulnerabilities(
            device['OS'], device['vendor'], device['device_name'])
        device['vulnerabilities'] = vulnerabilities
    device_manager.device_info = devices
    device_manager.save_device_info()
    return jsonify(devices)


if __name__ == '__main__':
    app.run(debug=True)
