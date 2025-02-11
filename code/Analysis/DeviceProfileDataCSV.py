class DeviceProfileDataCSV:
    def __init__(self, device_mac, source_address, destination_address, length, device_name = None):
        self.device_mac = device_mac
        self.length = length
        self.device_name = device_name
        self.source_address = source_address
        self.destination_address = destination_address

    def __hash__(self):
        return hash((self.device_mac, self.source_address, self.destination_address, self.length))

    def __eq__(self, other):
        return (self.device_mac, self.source_address, self.destination_address, self.length) == (
            other.device_mac, other.source_address, other.destination_address, other.length)