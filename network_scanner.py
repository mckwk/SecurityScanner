import socket

import netifaces
import nmap
from mac_vendor_lookup import MacLookup


class NetworkScanner:
    def __init__(self, nmap_path):
        self.nmap_path = nmap_path
        self.mac_lookup = MacLookup()

    def scan_network(self):
        try:
            target_ip = self._discover_network_address()
            nm = nmap.PortScanner(nmap_search_path=self.nmap_path)
            nm.scan(hosts=target_ip, arguments='-O -T4 -n')
            return [self._get_device_info(nm, host) for host in nm.all_hosts() if 'mac' in nm[host]['addresses']]
        except Exception as e:
            print(f"Error scanning network: {e}")
            return []

    def _discover_network_address(self):
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            netmask = self._get_netmask(local_ip)
            if netmask:
                return self._calculate_network_address(local_ip, netmask)
            else:
                raise RuntimeError("Unable to determine network address")
        except Exception as e:
            raise RuntimeError(f"Unable to determine network address: {e}")

    def _get_netmask(self, local_ip):
        try:
            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        if addr["addr"] == local_ip:
                            return addr.get("netmask")
            return None
        except Exception as e:
            print(f"Error getting netmask: {e}")
            return None

    def _calculate_network_address(self, ip, netmask):
        network_parts = [
            str(int(ip_part) & int(mask_part))
            for ip_part, mask_part in zip(ip.split("."), netmask.split("."))
        ]
        return ".".join(network_parts) + "/24"

    def _get_device_info(self, nm, host):
        addresses = nm[host]['addresses']
        mac = addresses['mac']
        return {
            'ip': addresses.get('ipv4', 'Unknown'),
            'mac': mac,
            'vendor': self._lookup_vendor(mac),
            'model': self._get_os_info(nm, host, 'osfamily', 'name', 'output'),
            'product_id': self._get_device_name(addresses.get('ipv4','Unknown')),
        }

    def _lookup_vendor(self, mac_address):
        try:
            return self.mac_lookup.lookup(mac_address)
        except Exception:
            return "Unknown"

    def _get_os_info(self, nm, host, *keys):
        try:
            for key in ['osclass', 'osmatch', 'hostscript']:
                if key in nm[host]:
                    for item in nm[host][key]:
                        for subkey in keys:
                            if subkey in item:
                                return item[subkey]
            return "Unknown"
        except Exception:
            return "Unknown"
        
    def _get_device_name(self, ip):
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except socket.herror:
            return "Unknown"
