import config
from device_manager import DeviceManager
from flask import Flask, jsonify, request
from log_and_file_managers.common_logger import logger
from log_and_file_managers.data_manager import DataManager
from network_utils.network_scanner import NetworkScanner
from vulnerability_utils.vulnerability_checker import VulnerabilityChecker

app = Flask(__name__)

network_scanner = NetworkScanner(nmap_path=config.NMAP_PATH, interfaces=config.NETWORK_INTERFACES if hasattr(
    config, 'NETWORK_INTERFACES') and config.NETWORK_INTERFACES else None)
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
    try:
        logger.info("Starting full network scan")
        network = request.args.get('network')
        devices = network_scanner.full_network_scan(network)
        return jsonify(devices)
    except Exception as e:
        logger.error(f"Error during full network scan: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/network_scan', methods=['GET'])
def network_scan():
    try:
        network = request.args.get('network')
        devices = network_scanner.scan_network(network)
        for device in devices:
            device['vulnerabilities'] = []
        device_manager.device_info = devices
        device_manager.save_device_info()
        return jsonify(devices)
    except Exception as e:
        logger.error(f"Error during network scan: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/search_vulnerabilities', methods=['POST'])
def search_vulnerabilities():
    try:
        vendor = request.form.get('vendor')
        os = request.form.get('os')
        device_info = request.form.get('device_info')
        vulnerabilities = vulnerability_checker.search_vulnerabilities(
            vendor, os, device_info)
        return jsonify(vulnerabilities)
    except Exception as e:
        logger.error(f"Error during vulnerability search: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/notification_history', methods=['GET'])
def notification_history():
    try:
        history = data_manager.load_notification_history()
        return jsonify(history)
    except Exception as e:
        logger.error(f"Error loading notification history: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/scan_vulnerabilities', methods=['POST'])
def scan_vulnerabilities():
    try:
        ip = request.args.get('ip')
        device_info = network_scanner._scan_single_ip(ip)
        vulnerabilities = vulnerability_checker.search_vulnerabilities(
            device_info['OS'], device_info['vendor'], device_info['device_name'])
        return jsonify(vulnerabilities)
    except Exception as e:
        logger.error(f"Error during vulnerability scan: {e}")
        return jsonify({"error": str(e)}), 500


@app.route('/scan_and_search_vulnerabilities', methods=['GET'])
def scan_and_search_vulnerabilities():
    try:
        network = request.args.get('network')
        devices = network_scanner.scan_network(network)
        for device in devices:
            vulnerabilities = vulnerability_checker.search_vulnerabilities(
                device['OS'], device['vendor'], device['device_name'])
            device['vulnerabilities'] = vulnerabilities
        device_manager.device_info = devices
        device_manager.save_device_info()
        return jsonify(devices)
    except Exception as e:
        logger.error(f"Error during scan and search vulnerabilities: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True)
