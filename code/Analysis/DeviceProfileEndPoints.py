class DeviceProfileEndPoints:
    def __init__(self, device_mac, packet_direction):
        self.device_mac = device_mac
        self.packet_direction = packet_direction
        self.external_address_list = set()
    def __hash__(self):
        return hash((self.device_mac, self.packet_direction))

    def __eq__(self, other):
        return (self.device_mac, self.packet_direction) == (
            other.device_mac, other.packet_direction)