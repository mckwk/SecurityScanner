import nmap
from mac_vendor_lookup import MacLookup
import socket
import netifaces

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
            return []

    def _discover_network_address(self):
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            netmask = self._get_netmask(local_ip)

            if netmask:
                network_parts = [
                    str(int(ip_part) & int(mask_part))
                    for ip_part, mask_part in zip(local_ip.split("."), netmask.split("."))
                ]
                network_address = ".".join(network_parts) + "/24"
                return network_address
            else:
                raise RuntimeError("Unable to determine network address")
        except Exception as e:
            raise RuntimeError("Unable to determine network address")

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
            return None

    def _get_device_info(self, nm, host):
        addresses = nm[host]['addresses']
        mac = addresses['mac']
        return {
            'ip': addresses['ipv4'],
            'mac': mac,
            'vendor': self._lookup_vendor(mac),
            'model': self._get_os_info(nm, host, 'osfamily', 'name', 'output'),
            'product_id': self._get_os_info(nm, host, 'cpe', 'cpe', 'output'),
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