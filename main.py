import nmap
from mac_vendor_lookup import MacLookup

nmap_path = [r"C:\Nmap\nmap.exe"]

def scan_network():
    # Define the network range to scan
    target_ip = "192.168.5.0/24"
    
    # Initialize the Nmap scanner
    nm = nmap.PortScanner(nmap_search_path=nmap_path)
    
    # Perform the scan
    nm.scan(hosts=target_ip, arguments='-sn')

    # Dictionary to store device information
    devices = []

    # Initialize the MacLookup instance
    mac_lookup = MacLookup()

    # Process the scan results
    for host in nm.all_hosts():
        if 'mac' in nm[host]['addresses']:
            device_info = {
                'ip': nm[host]['addresses']['ipv4'],
                'mac': nm[host]['addresses']['mac'],
                'vendor': "Unknown",
                'model': "Unknown",
                'product_model': "Unknown"
            }

            # Get vendor information from MAC address
            try:
                device_info['vendor'] = mac_lookup.lookup(device_info['mac'])
            except:
                pass

            devices.append(device_info)

    # Print detailed device information
    for device in devices:
        print(f"Device found at IP: {device['ip']}")
        print(f"  MAC Address: {device['mac']}")
        print(f"  Vendor: {device['vendor']}")
        print(f"  Model: {device['model']}")
        print(f"  Product Model: {device['product_model']}")
        print()

# Call the scan_network function to start the scanning process
scan_network()