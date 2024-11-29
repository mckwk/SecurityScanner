import socket
import logging
import netifaces
import nmap
from mac_vendor_lookup import MacLookup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class NetworkScanner:
    def __init__(self, nmap_path):
        self.nmap_path = nmap_path
        self.mac_lookup = MacLookup()
        logging.info("NetworkScanner initialized with nmap path: %s", nmap_path)

    def scan_network(self):
        try:
            target_ip = self._discover_network_address()
            logging.info("Target IP for scanning: %s", target_ip)
            nm = nmap.PortScanner(nmap_search_path=self.nmap_path)
            nm.scan(hosts=target_ip, arguments='-O -T4 -n')
            devices = [self._get_device_info(nm, host) for host in nm.all_hosts() if 'mac' in nm[host]['addresses']]
            logging.info("Scan completed. Devices found: %d", len(devices))
            return devices
        except Exception as e:
            logging.error("Error scanning network: %s", e)
            return []

    def _discover_network_address(self):
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            logging.info("Local IP address: %s", local_ip)
            netmask = self._get_netmask(local_ip)
            if netmask:
                network_address = self._calculate_network_address(local_ip, netmask)
                logging.info("Network address: %s", network_address)
                return network_address
            else:
                raise RuntimeError("Unable to determine network address")
        except Exception as e:
            logging.error("Unable to determine network address: %s", e)
            raise RuntimeError(f"Unable to determine network address: {e}")

    def _get_netmask(self, local_ip):
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr["addr"] == local_ip:
                            netmask = addr.get("netmask")
                            logging.info("Netmask for interface %s: %s", iface, netmask)
                            return netmask
            return None
        except Exception as e:
            logging.error("Error getting netmask: %s", e)
            return None

    def _calculate_network_address(self, ip, netmask):
        network_parts = [
            str(int(ip_part) & int(mask_part))
            for ip_part, mask_part in zip(ip.split("."), netmask.split("."))
        ]
        network_address = ".".join(network_parts) + "/24"
        logging.info("Calculated network address: %s", network_address)
        return network_address

    def _get_device_info(self, nm, host):
        addresses = nm[host]['addresses']
        mac = addresses['mac']
        device_info = {
            'ip': addresses.get('ipv4', 'Unknown'),
            'mac': mac,
            'vendor': self._lookup_vendor(mac),
            'OS': self._get_os_info(nm, host, 'osfamily', 'name', 'output'),
            'device_name': self._get_os_info(nm, host, 'cpe', 'cpe', 'output'),
        }
        logging.info("Device info for host %s: %s", host, device_info)
        return device_info
    
    def _scan_single_ip(self, ip):
        try:
            nm = nmap.PortScanner(nmap_search_path=self.nmap_path)
            nm.scan(hosts=ip, arguments='-O -T4 -n')
            if ip in nm.all_hosts() and 'mac' in nm[ip]['addresses']:
                device_info = self._get_device_info(nm, ip)
                logging.info("Scan completed for IP %s. Device info: %s", ip, device_info)
                return device_info
            else:
                logging.warning("No device found at IP %s", ip)
                return None
        except Exception as e:
            logging.error("Error scanning IP %s: %s", ip, e)
            return None

    def _lookup_vendor(self, mac_address):
        try:
            vendor = self.mac_lookup.lookup(mac_address)
            logging.info("Vendor lookup for MAC %s: %s", mac_address, vendor)
            return vendor
        except Exception:
            logging.warning("Vendor lookup failed for MAC %s", mac_address)
            return "Unknown"

    def _get_os_info(self, nm, host, *keys):
        try:
            for key in ['osclass', 'osmatch', 'hostscript']:
                if key in nm[host]:
                    for item in nm[host][key]:
                        for subkey in keys:
                            if subkey in item:
                                os_info = item[subkey]
                                logging.info("OS info for host %s: %s", host, os_info)
                                return os_info
            return "Unknown"
        except Exception:
            logging.warning("OS info lookup failed for host %s", host)
            return "Unknown"
