class DeviceIpMapping:
    def __init__(self, device_mac, ip_address):
        self.device_mac = device_mac
        self.ip_address = ip_address

    def __hash__(self):
        return hash((self.device_mac, self.ip_address))

    def __eq__(self, other):
        return (self.device_mac, self.ip_address) == (
            other.device_mac, other.ip_address)