import nmap

nmap_path = [r"C:\Nmap\nmap.exe"]

def scan_network():
    try:
        # Create a new instance of the PortScanner class
        scanner = nmap.PortScanner(nmap_search_path=nmap_path)

        # Scan the network for devices with common smart home ports, OS detection, and version detection
        scanner.scan(hosts='192.168.5.0/24', arguments='-O -sV -p 80,443,8080,554,8883,5353')

        # Iterate over the scan results and print the found devices with their types
        for host in scanner.all_hosts():
            if 'tcp' in scanner[host]:
                device_type = "Unknown"
                device_vendor = "Unknown"
                device_model = "Unknown"
                product_model = "Unknown"
                device_services = []

                # Check for OS match information
                if 'osmatch' in scanner[host]:
                    for osmatch in scanner[host]['osmatch']:
                        if 'osclass' in osmatch:
                            for osclass in osmatch['osclass']:
                                if 'type' in osclass:
                                    device_type = osclass['type']
                                if 'vendor' in osclass:
                                    device_vendor = osclass['vendor']
                                if 'osfamily' in osclass:
                                    device_model = osclass['osfamily']
                                if 'osgen' in osclass:
                                    device_model += f" {osclass['osgen']}"
                                break

                # Check for service information
                for port in scanner[host]['tcp']:
                    service = scanner[host]['tcp'][port]['name']
                    product = scanner[host]['tcp'][port].get('product', '')
                    version = scanner[host]['tcp'][port].get('version', '')
                    extrainfo = scanner[host]['tcp'][port].get('extrainfo', '')
                    service_info = f"{service} {product} {version} {extrainfo}".strip()
                    device_services.append(service_info)

                    # Check for product model in service information
                    if product:
                        product_model = product

                # Check for MAC address vendor information
                if 'mac' in scanner[host]:
                    mac_address = scanner[host]['mac']
                    device_vendor = scanner[host]['vendor'].get(mac_address, "Unknown")

                # Print detailed device information
                print(f"Device found at IP: {host}")
                print(f"  Type: {device_type}")
                print(f"  Vendor: {device_vendor}")
                print(f"  Model: {device_model}")
                print(f"  Product Model: {product_model}")
                print(f"  Services: {', '.join(device_services)}")
                print()

    except nmap.PortScannerError as e:
        print(f"PortScannerError: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Call the scan_network function to start the scanning process
scan_network()