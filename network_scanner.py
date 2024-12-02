import socket

import netifaces
import nmap
from mac_vendor_lookup import MacLookup

import config
from log_and_file_managers.logger_manager import LoggerManager

logger_manager = LoggerManager(config.LOG_FILE)
logger = logger_manager.get_logger()


class NetworkScanner:
    def __init__(self, nmap_path):
        self.nmap_path = nmap_path
        self.mac_lookup = MacLookup()
        logger.info("NetworkScanner initialized with nmap path: %s", nmap_path)

    def scan_network(self):
        try:
            target_ip = self._discover_network_address()
            logger.info("Target IP for scanning: %s", target_ip)
            nm = nmap.PortScanner(nmap_search_path=self.nmap_path)
            nm.scan(hosts=target_ip, arguments='-O -T4 -n')
            devices = [self._get_device_info(nm, host) for host in nm.all_hosts() if 'mac' in nm[host]['addresses']]
            logger.info("Scan completed. Devices found: %d", len(devices))
            return devices
        except Exception as e:
            logger.error("Error scanning network: %s", e)
            return []

    def _discover_network_address(self):
        try:
            local_ip = self._get_local_ip()
            netmask = self._get_netmask(local_ip)
            if netmask:
                return self._calculate_network_address(local_ip, netmask)
            else:
                raise RuntimeError("Unable to determine network address")
        except Exception as e:
            logger.error("Unable to determine network address: %s", e)
            raise RuntimeError(f"Unable to determine network address: {e}")

    def _get_local_ip(self):
        local_ip = socket.gethostbyname(socket.gethostname())
        logger.info("Local IP address: %s", local_ip)
        return local_ip

    def _get_netmask(self, local_ip):
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr["addr"] == local_ip:
                            netmask = addr.get("netmask")
                            logger.info("Netmask for interface %s: %s", iface, netmask)
                            return netmask
            return None
        except Exception as e:
            logger.error("Error getting netmask: %s", e)
            return None

    def _calculate_network_address(self, ip, netmask):
        network_parts = [str(int(ip_part) & int(mask_part)) for ip_part, mask_part in zip(ip.split("."), netmask.split("."))]
        network_address = ".".join(network_parts) + "/24"
        logger.info("Calculated network address: %s", network_address)
        return network_address

    def _get_device_info(self, nm, host):
        addresses = nm[host]['addresses']
        mac = addresses['mac']
        device_info = {
            'ip': addresses.get('ipv4', 'Unknown'),
            'mac': mac,
            'vendor': self._lookup_vendor(mac),
            'OS': self._get_os_info(nm, host),
            'device_name': self._get_device_name(addresses.get('ipv4', 'Unknown')),
        }
        logger.info("Device info for host %s: %s", host, device_info)
        return device_info

    def _scan_single_ip(self, ip):
        try:
            nm = nmap.PortScanner(nmap_search_path=self.nmap_path)
            nm.scan(hosts=ip, arguments='-O -T4 -n')
            if ip in nm.all_hosts() and 'mac' in nm[ip]['addresses']:
                return self._get_device_info(nm, ip)
            else:
                logger.warning("No device found at IP %s", ip)
                return None
        except Exception as e:
            logger.error("Error scanning IP %s: %s", ip, e)
            return None

    def _lookup_vendor(self, mac_address):
        try:
            vendor = self.mac_lookup.lookup(mac_address)
            logger.info("Vendor lookup for MAC %s: %s", mac_address, vendor)
            return vendor
        except Exception:
            logger.warning("Vendor lookup failed for MAC %s", mac_address)
            return "Unknown"

    def _get_os_info(self, nm, host):
        try:
            for key in ['osclass', 'osmatch', 'hostscript']:
                if key in nm[host]:
                    for item in nm[host][key]:
                        for subkey in ['osfamily', 'name', 'output']:
                            if subkey in item:
                                os_info = item[subkey]
                                logger.info("OS info for host %s: %s", host, os_info)
                                return os_info
            return "Unknown"
        except Exception:
            logger.warning("OS info lookup failed for host %s", host)
            return "Unknown"

    def _get_device_name(self, ip):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            logger.info("Hostname for IP %s: %s", ip, hostname)
            return hostname.replace('.lan', '')
        except socket.herror:
            logger.warning("Hostname lookup failed for IP %s", ip)
            return "Unknown"
