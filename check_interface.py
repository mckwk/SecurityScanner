import netifaces


def list_interfaces():
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            ip_info = addrs[netifaces.AF_INET][0]
            print(f"Interface: {iface}")
            print(f"  IP Address: {ip_info['addr']}")
            print(f"  Netmask: {ip_info['netmask']}")
            print()


list_interfaces()
