from yeelight import Bulb, discover_bulbs

def get_bulb_info(bulb):
    properties = bulb.get_properties()
    model = bulb.get_properties()['name']
    return {
        'model': model,
        'fw_ver': properties.get('fw_ver', 'Unknown'),
        'power': properties.get('power', 'Unknown'),
        'bright': properties.get('bright', 'Unknown'),
        'color_mode': properties.get('color_mode', 'Unknown'),
        'ct': properties.get('ct', 'Unknown'),
        'rgb': properties.get('rgb', 'Unknown'),
        'hue': properties.get('hue', 'Unknown'),
        'sat': properties.get('sat', 'Unknown')
    }

bulb1 = Bulb("192.168.5.215")
bulb1.turn_off()
bulb1_info = get_bulb_info(bulb1)


bulb2 = Bulb("192.168.5.13")
bulb2.turn_off()
bulb2_info = get_bulb_info(bulb2)

print("Bulb 1 Info:")
for key, value in bulb1_info.items():
    print(f"  {key}: {value}")
print(bulb1.bulb_type, bulb1.get_model_specs())

print("\nBulb 2 Info:")
for key, value in bulb2_info.items():
    print(f"  {key}: {value}")
print(bulb2.bulb_type, bulb2.get_model_specs())

