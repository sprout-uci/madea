class DeviceProfileData:
    def __init__(self, device_mac, packet_direction, server_address, length, device_name = None,):
        self.device_mac = device_mac
        self.length = length
        self.device_name = device_name
        self.server_address = server_address
        self.packet_direction = packet_direction

    def __hash__(self):
        return hash((self.device_mac, self.packet_direction, self.server_address, self.length))

    def __eq__(self, other):
        return (self.device_mac, self.packet_direction, self.server_address, self.length) == (
            other.device_mac, other.packet_direction, other.server_address, other.length)