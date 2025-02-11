class EndPointInfo:
    def __init__(self, device_mac, source_address, destination_address):
        self.device_mac = device_mac
        self.source_address = source_address
        self.destination_address = destination_address

    def __hash__(self):
        return hash((self.device_mac, self.source_address, self.destination_address))

    def __eq__(self, other):
        return (self.device_mac, self.source_address, self.destination_address) == (
            other.device_mac, other.packet_direction, other.server_address)
