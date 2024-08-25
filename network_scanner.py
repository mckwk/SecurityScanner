import nmap
from mac_vendor_lookup import MacLookup

class NetworkScanner:
    def __init__(self, nmap_path):
        """
        Initialize the NetworkScanner with the path to the nmap executable.
        
        Args:
            nmap_path (list): List of paths to the nmap executable.
        """
        self.nmap_path = nmap_path
        self.mac_lookup = MacLookup()

    def scan_network(self, target_ip):
        """
        Scan the network for devices.
        
        Args:
            target_ip (str): The target IP range to scan.
        
        Returns:
            list: A list of dictionaries containing device information.
        """
        nm = nmap.PortScanner(nmap_search_path=self.nmap_path)
        nm.scan(hosts=target_ip, arguments='-O')
        return [self._get_device_info(nm, host) for host in nm.all_hosts() if 'mac' in nm[host]['addresses']]

    def _get_device_info(self, nm, host):
        """
        Get device information for a given host.
        
        Args:
            nm (nmap.PortScanner): The nmap PortScanner instance.
            host (str): The host IP address.
        
        Returns:
            dict: A dictionary containing device information.
        """
        device_info = {
            'ip': nm[host]['addresses']['ipv4'],
            'mac': nm[host]['addresses']['mac'],
            'vendor': self._lookup_vendor(nm[host]['addresses']['mac']),
            'model': self._get_model(nm, host),
        }
        return device_info

    def _lookup_vendor(self, mac_address):
        """
        Lookup the vendor for a given MAC address.
        
        Args:
            mac_address (str): The MAC address to lookup.
        
        Returns:
            str: The vendor name or "Unknown" if not found.
        """
        try:
            return self.mac_lookup.lookup(mac_address)
        except Exception:
            return "Unknown"

    def _get_model(self, nm, host):
        """
        Get the model information from nmap scan results.
        
        Args:
            nm (nmap.PortScanner): The nmap PortScanner instance.
            host (str): The host IP address.
        
        Returns:
            str: The model information or "Unknown" if not found.
        """
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