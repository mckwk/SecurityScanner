import nmap
from mac_vendor_lookup import MacLookup

class NetworkScanner:
    def __init__(self, nmap_path):
        self.nmap_path = nmap_path
        self.mac_lookup = MacLookup()

    def scan_network(self, target_ip):
        nm = nmap.PortScanner(nmap_search_path=self.nmap_path)
        nm.scan(hosts=target_ip, arguments='-O')
        return [self._get_device_info(nm, host) for host in nm.all_hosts() if 'mac' in nm[host]['addresses']]

    def _get_device_info(self, nm, host):
        return {
            'ip': nm[host]['addresses']['ipv4'],
            'mac': nm[host]['addresses']['mac'],
            'vendor': self._lookup_vendor(nm[host]['addresses']['mac']),
            'model': self._get_model(nm, host),
            'product_id': self._get_product_id(nm, host),
        }

    def _lookup_vendor(self, mac_address):
        try:
            return self.mac_lookup.lookup(mac_address)
        except Exception:
            return "Unknown"

    def _get_model(self, nm, host):
        try:
            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    if 'osfamily' in osclass:
                        return osclass['osfamily']
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    if 'name' in osmatch:
                        return osmatch['name']
            if 'hostscript' in nm[host]:
                for script in nm[host]['hostscript']:
                    if 'output' in script:
                        return script['output']
            return "Unknown"
        except Exception:
            return "Unknown"

    def _get_product_id(self, nm, host):
        try:
            if 'osclass' in nm[host]:
                for osclass in nm[host]['osclass']:
                    if 'cpe' in osclass:
                        return osclass['cpe']
            if 'osmatch' in nm[host]:
                for osmatch in nm[host]['osmatch']:
                    if 'cpe' in osmatch:
                        return osmatch['cpe']
            if 'hostscript' in nm[host]:
                for script in nm[host]['hostscript']:
                    if 'output' in script:
                        return script['output']
            return "Unknown"
        except Exception:
            return "Unknown"