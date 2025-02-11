class DeviceProfileEndPointsCSV:
    def __init__(self, device_mac):
        self.device_mac = device_mac
        self.end_point_list = set()
