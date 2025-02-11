import csv
import os
from os.path import exists
from Analysis.DeviceProfileData import DeviceProfileData
from Analysis.DeviceProfileDataCSV import DeviceProfileDataCSV
from Analysis.DeviceProfileEndPoints import DeviceProfileEndPoints
from Analysis.DeviceProfileEndPointsCSV import DeviceProfileEndPointsCSV
from Analysis.EndPointInfo import EndPointInfo
from Utils.ConstantValues import ConstantValues
import tldextract
from difflib import SequenceMatcher as SM

class PacketUtil:
    def __init__(self, dns_util):
        self.constant_values = ConstantValues()
        self.dns_util = dns_util

    def get_destination_ip_address(self, packet, packet_type, device_mac=None):
        destination_ip_address = ''
        if packet_type==self.constant_values.PACKET_TYPE_CSV:
            destination_ip_address = packet[2]
        else:
            protocol = packet.highest_layer
            if hasattr(packet, 'ip'):
                destination_ip_address = packet.ip.dst
            elif hasattr(packet, 'ipv6'):
                destination_ip_address = packet.ipv6.dst
            elif protocol == 'ARP':
                destination_ip_address = packet[protocol].dst_proto_ipv4
        # get corresponding host name if available
        if not destination_ip_address.startswith(self.constant_values.LAN_ADDRESS_PREFIX):
            destination_ip_address = self.dns_util.get_host_address(destination_ip_address, device_mac)
        return destination_ip_address

    def get_source_ip_address(self, packet, packet_type, device_mac=None):
        source_ip_address = ''
        if packet_type==self.constant_values.PACKET_TYPE_CSV:
            source_ip_address = packet[1]
        else:
            protocol = packet.highest_layer
            if hasattr(packet, 'ip'):
                source_ip_address = packet.ip.src
            elif hasattr(packet, 'ipv6'):
                source_ip_address = packet.ipv6.src
            elif protocol == 'ARP':
                source_ip_address = packet[protocol].src_proto_ipv4
        # get corresponding host name if available
        if not source_ip_address.startswith(self.constant_values.LAN_ADDRESS_PREFIX):
            source_ip_address = self.dns_util.get_host_address(source_ip_address, device_mac)
        return source_ip_address

    def get_source_mac_address(self, packet):
        source_mac_address = packet.eth.src
        return source_mac_address

    def get_destination_mac_address(self, packet):
        destination_mac_address = packet.eth.dst
        return destination_mac_address

    def get_source_port(self, packet):
        source_port = '-1'
        if hasattr(packet, 'tcp'):
            source_port = packet.tcp.srcport
        elif hasattr(packet, 'udp'):
            source_port = packet.udp.srcport
        return int(source_port)

    def get_destination_port(self, packet):
        destination_port = '-1'
        if hasattr(packet, 'tcp'):
            destination_port = packet.tcp.dstport
        elif hasattr(packet, 'udp'):
            destination_port = packet.udp.dstport
        return int(destination_port)

    def is_ip_and_tcp_packet(self, packet):
        if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
            return True
        return False

    def is_ip_packet(self, packet):
        if hasattr(packet, 'ip'):
            return True
        return False

    def is_configuration_packet(self, packet, packet_type=None):
        if packet_type == self.constant_values.PACKET_TYPE_CSV:
            protocol = packet[3]
            if protocol=='DNS' or protocol=='MDNS' or protocol=='ARP' or protocol=='NTP' or protocol=='NBNS' or \
                protocol=='IGMPv3' or protocol=='DHCP':
                return True
        else:
            if (hasattr(packet, 'dns') and int(packet.dns.flags_response) != 1) or hasattr(packet, 'mdns') or hasattr(
                    packet, 'ntp') or hasattr(packet, 'dhcp') or \
                    hasattr(packet, 'bootp') or hasattr(packet, 'eapol') or hasattr(packet, 'arp'):
                return True
        return False

    def is_dns_response_packet(self, packet):
        if hasattr(packet, 'dns') and int(packet.dns.flags_response) == 1:
            return True
        return False

    def get_length(self, packet):
        return int(packet.length)

    def get_protocol(self, packet):
        return packet.highest_layer

    def get_snif_time(self, packet):
        return packet.sniff_time

    def get_existing_device_profiles(self, root_path):
        device_profile_data = dict()
        profile_endpoints_map = dict()
        device_profile_csv_path = os.path.join(root_path, self.constant_values.DEVICE_PROFILE_CSV_FILE_NAME)
        with open(device_profile_csv_path, 'r', encoding='UTF8', newline='') as f:
            reader = csv.reader(f)
            count = 0
            for row in reader:
                count += 1
                if count == 1:
                    continue
                device_mac = row[0]
                packet_direction = row[1]
                server_address = row[2]
                length = int(row[3])
                device_name = row[4]

                key_profile_endpoints = DeviceProfileEndPoints(device_mac, packet_direction)
                device_profile_end_points = profile_endpoints_map.get(key_profile_endpoints)
                if device_profile_end_points is None:
                    device_profile_end_points = DeviceProfileEndPoints(device_mac, packet_direction)
                device_profile_end_points.external_address_list.add(server_address)
                profile_endpoints_map[key_profile_endpoints] = device_profile_end_points
                key_device_profile = DeviceProfileData(device_mac, packet_direction, server_address, length)
                device_profile = device_profile_data.get(key_device_profile)
                if device_profile is None:
                    device_profile = DeviceProfileData(device_mac, packet_direction, server_address, length, device_name)
                device_profile_data[key_device_profile] = device_profile
            return device_profile_data, profile_endpoints_map
    def get_existing_csv_device_profiles(self, root_path):
        device_profile_data = dict()
        profile_endpoints_map = dict()
        device_profile_csv_path = os.path.join(root_path, self.constant_values.DEVICE_PROFILE_CSV_FILE_NAME)
        with open(device_profile_csv_path, 'r', encoding='UTF8', newline='') as f:
            reader = csv.reader(f)
            count = 0
            for row in reader:
                count += 1
                if count == 1:
                    continue
                device_mac = row[0]
                source_address = row[1]
                destination_address = row[2]
                length = int(row[3])
                device_name = row[4]
                end_point_info = EndPointInfo(device_mac, source_address, destination_address)
                device_profile_end_points = profile_endpoints_map.get(device_mac)
                if device_profile_end_points is None:
                    device_profile_end_points = DeviceProfileEndPointsCSV(device_mac)
                device_profile_end_points.end_point_list.add(end_point_info)
                profile_endpoints_map[device_mac] = device_profile_end_points
                key_device_profile = DeviceProfileDataCSV(device_mac, source_address, destination_address, length)
                device_profile = device_profile_data.get(key_device_profile)
                if device_profile is None:
                    device_profile = DeviceProfileData(device_mac, source_address, destination_address, length, device_name)
                device_profile_data[key_device_profile] = device_profile
            return device_profile_data, profile_endpoints_map

    def save_device_profiles_to_csv(self, device_profile_data, device_packet_num, root_path, operation, file_name=None):
        profile_counts = dict()
        device_mac_name_mapping = dict()
        if file_name is None:
            file_name = self.constant_values.DEVICE_PROFILE_CSV_FILE_NAME
        device_profile_csv_path = os.path.join(root_path, file_name)
        device_profile_csv_header = ['DEVICE_MAC', 'PACKET_DIRECTION', 'SERVER_ADDRESS',
                                     'PACKET_LENGTH', 'DEVICE_NAME']
        if exists(device_profile_csv_path):
            with open(device_profile_csv_path, 'a', encoding='UTF8', newline='') as f:
                writer = csv.writer(f)
                for element in device_profile_data.values():
                    device_profile_count = profile_counts.get(element.device_mac)
                    device_mac_name_mapping[element.device_mac] = element.device_name
                    if device_profile_count is None:
                        device_profile_count = 0
                    device_profile_count += 1
                    profile_counts[element.device_mac] = device_profile_count
                    row_value = [element.device_mac, element.packet_direction, element.server_address, element.length,
                                 element.device_name]
                    writer.writerow(row_value)
        else:
            with open(device_profile_csv_path, 'w', encoding='UTF8', newline='') as f:
                writer = csv.writer(f)
                # write the header
                writer.writerow(device_profile_csv_header)
                for element in device_profile_data.values():
                    device_profile_count = profile_counts.get(element.device_mac)
                    device_mac_name_mapping[element.device_mac]=element.device_name
                    if device_profile_count is None:
                        device_profile_count = 0
                    device_profile_count += 1
                    profile_counts[element.device_mac] = device_profile_count
                    row_value = [element.device_mac, element.packet_direction, element.server_address, element.length,
                                 element.device_name]
                    writer.writerow(row_value)
        if operation == self.constant_values.SYSTEM_OPERATION_PROFILING:
            profile_count_csv_path = os.path.join(root_path, self.constant_values.PROFILE_COUNT_CSV_FILE_NAME_PROFILING)
        else:
            profile_count_csv_path = os.path.join(root_path, self.constant_values.PROFILE_COUNT_CSV_FILE_NAME_MONITORING)
        profile_count_csv_header = ['DEVICE_NAME', 'DEVICE_MAC', 'TOTAL_PACKETS', 'TOTAL_PROFILE_ENTRIES']
        with open(profile_count_csv_path, 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            # write the header
            writer.writerow(profile_count_csv_header)
            for device_mac in profile_counts.keys():
                device_name = device_mac_name_mapping.get(device_mac)
                device_profile_count = profile_counts.get(device_mac)
                total_packets = device_packet_num.get(device_mac)
                row_value = [device_name, device_mac, total_packets, device_profile_count]
                writer.writerow(row_value)
    def save_csv_device_profiles_to_csv(self, device_profile_data, device_packet_num, root_path, operation, file_name=None):
        profile_counts = dict()
        device_mac_name_mapping = dict()
        if file_name is None:
            file_name = self.constant_values.DEVICE_PROFILE_CSV_FILE_NAME
        device_profile_csv_path = os.path.join(root_path, file_name)
        device_profile_csv_header = ['DEVICE_MAC', 'SOURCE_ADDRESS', 'DESTINATION_ADDRESS',
                                     'PACKET_LENGTH', 'DEVICE_NAME']
        if exists(device_profile_csv_path):
            with open(device_profile_csv_path, 'a', encoding='UTF8', newline='') as f:
                writer = csv.writer(f)
                for element in device_profile_data.values():
                    device_profile_count = profile_counts.get(element.device_mac)
                    device_mac_name_mapping[element.device_mac] = element.device_name
                    if device_profile_count is None:
                        device_profile_count = 0
                    device_profile_count += 1
                    profile_counts[element.device_mac] = device_profile_count
                    row_value = [element.device_mac, element.source_address, element.destination_address, element.length,
                                 element.device_name]
                    writer.writerow(row_value)
        else:
            with open(device_profile_csv_path, 'w', encoding='UTF8', newline='') as f:
                writer = csv.writer(f)
                # write the header
                writer.writerow(device_profile_csv_header)
                for element in device_profile_data.values():
                    device_profile_count = profile_counts.get(element.device_mac)
                    device_mac_name_mapping[element.device_mac]=element.device_name
                    if device_profile_count is None:
                        device_profile_count = 0
                    device_profile_count += 1
                    profile_counts[element.device_mac] = device_profile_count
                    row_value = [element.device_mac, element.source_address, element.destination_address, element.length,
                                 element.device_name]
                    writer.writerow(row_value)
        if operation == self.constant_values.SYSTEM_OPERATION_PROFILING:
            profile_count_csv_path = os.path.join(root_path, self.constant_values.PROFILE_COUNT_CSV_FILE_NAME_PROFILING)
        else:
            profile_count_csv_path = os.path.join(root_path, self.constant_values.PROFILE_COUNT_CSV_FILE_NAME_MONITORING)
        profile_count_csv_header = ['DEVICE_NAME', 'DEVICE_MAC', 'TOTAL_PACKETS', 'TOTAL_PROFILE_ENTRIES']
        with open(profile_count_csv_path, 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            # write the header
            writer.writerow(profile_count_csv_header)
            for device_mac in profile_counts.keys():
                device_name = device_mac_name_mapping.get(device_mac)
                device_profile_count = profile_counts.get(device_mac)
                total_packets = device_packet_num.get(device_mac)
                row_value = [device_name, device_mac, total_packets, device_profile_count]
                writer.writerow(row_value)
    def save_timing_statistics_to_csv(self, totoal_time, total_packet_num, root_path, csv_name):
        try:
            timing_statistics_csv_path = os.path.join(root_path, csv_name)
            total_time_msec = totoal_time*1000
            average_running_time_msec = (total_time_msec/total_packet_num)
            row_value = [total_time_msec, total_packet_num, average_running_time_msec]
            if exists(timing_statistics_csv_path):
                with open(timing_statistics_csv_path, 'a', encoding='UTF8', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(row_value)
            else:
                with open(timing_statistics_csv_path, 'w', encoding='UTF8', newline='') as f:
                    writer = csv.writer(f)
                    # write the header
                    timing_statistics_csv_header = ['TOTAL_TIME_MILISECOND', 'TOTAL_PACKETS', 'AVERAGE_MATCHING_TIME_MILISECOND']
                    writer.writerow(timing_statistics_csv_header)
                    # write the value
                    writer.writerow(row_value)
        except:
            pass
    def save_monitoring_stat_to_csv(self, device_packet_num, device_suspicious_packet_num, device_suspicious_packet_num_endpoint_mismatch, device_name_mapping,
                                    root_path, csv_name):
        device_packet_num_csv_path = os.path.join(root_path, csv_name)
        device_packet_num_csv_header = ['DEVICE_NAME', 'DEVICE_MAC', 'TOTAL_PACKET_NUM', 'SUSPICIOUS_PACKET_NUM',
                                        'SUSPICIOUS_PACKET_NUM_ENDPOINTS', 'FALSE_POSITIVE_RATE', 'FALSE_POSITIVE_RATE_ENDPOINTS']
        with open(device_packet_num_csv_path, 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            # write the header
            writer.writerow(device_packet_num_csv_header)
            for device_mac, total_packet_num in device_packet_num.items():
                device_name = device_name_mapping.get(device_mac)
                suspicious_packet_num = device_suspicious_packet_num.get(device_mac)
                if suspicious_packet_num is None:
                    suspicious_packet_num = 0
                false_positive = (suspicious_packet_num / total_packet_num) * 100
                suspicious_packet_num_endpoint = device_suspicious_packet_num_endpoint_mismatch.get(device_mac)
                if suspicious_packet_num_endpoint is None:
                    suspicious_packet_num_endpoint = 0
                false_positive_endpoint = (suspicious_packet_num_endpoint / total_packet_num) * 100
                row_value = [device_name, device_mac, total_packet_num, suspicious_packet_num, suspicious_packet_num_endpoint, false_positive, false_positive_endpoint]
                writer.writerow(row_value)

    def save_device_profile_counts(self, root_path):
        profile_csv_path = os.path.join(root_path, self.constant_values.DEVICE_PROFILE_CSV_FILE_NAME)
        profile_counts = dict()
        device_mac_name_mapping = dict()
        with open(profile_csv_path, 'r', encoding='UTF8', newline='') as f:
            reader = csv.reader(f)
            count = 0
            for row in reader:
                count += 1
                if count == 1:
                    continue
                device_mac = row[0]
                device_name = device_name = row[4]
                device_profile_count = profile_counts.get(device_mac)
                if device_profile_count is None:
                    device_profile_count = 0
                device_profile_count += 1
                profile_counts[device_mac] = device_profile_count
                device_mac_name_mapping[device_mac] = device_name

        profile_count_csv_path = os.path.join(root_path, self.constant_values.PROFILE_COUNT_CSV_FILE_NAME_PROFILING)
        profile_count_csv_header = ['DEVICE_NAME', 'DEVICE_MAC', 'TOTAL_PROFILE_ENTRIES']
        with open(profile_count_csv_path, 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            # write the header
            writer.writerow(profile_count_csv_header)
            for device_mac in profile_counts.keys():
                device_name = device_mac_name_mapping.get(device_mac)
                device_profile_count = profile_counts.get(device_mac)
                row_value = [device_name, device_mac, device_profile_count]
                writer.writerow(row_value)

    def get_device_mac_name_mapping(self, root_path):
        device_mac_name_mapping = dict()
        mapping_path = os.path.join(root_path, self.constant_values.DEVICE_MAC_NAME_MAPPING_CSV_FILE)
        with open(mapping_path, 'r', encoding='UTF8', newline='') as f:
            reader = csv.reader(f)
            count = 0
            for row in reader:
                count += 1
                if count == 1:
                    continue
                device_mac = row[0]
                device_name = row[1]
                device_mac_name_mapping[device_mac] = device_name
        return device_mac_name_mapping

    def get_device_mac_list(self, root_path, operation):
        device_mac_list = []
        if operation == self.constant_values.SYSTEM_OPERATION_PROFILING:
            mapping_path = os.path.join(root_path, self.constant_values.PROFILING_DEVICE_MAC_LIST_CSV_FILE)
        else:
            mapping_path = os.path.join(root_path, self.constant_values.MONITORING_DEVICE_MAC_LIST_CSV_FILE)
        with open(mapping_path, 'r', encoding='UTF8', newline='') as f:
            reader = csv.reader(f)
            for row in reader:
                device_mac_list.append(row[0])
        return device_mac_list

    def get_device_name_mac_mapping(self, root_path):
        device_name_mac_mapping = dict()
        mapping_path = os.path.join(root_path, self.constant_values.DEVICE_NAME_MAC_MAPPING_CSV_FILE)
        with open(mapping_path, 'r', encoding='UTF8', newline='') as f:
            reader = csv.reader(f)
            count = 0
            for row in reader:
                count += 1
                if count == 1:
                    continue
                device_name = row[0]
                device_mac = row[1]
                device_name_mac_mapping[device_name] = device_mac
        return device_name_mac_mapping

    def get_monitoring_stat(self, root_path, csv_name):
        suspicious_packet_num = dict()
        suspicious_packet_num_endpoint_mismatch = dict()
        total_packets = dict()
        device_packet_num_csv_path = os.path.join(root_path, csv_name)
        with open(device_packet_num_csv_path, 'r', encoding='UTF8', newline='') as f:
            reader = csv.reader(f)
            count = 0
            for row in reader:
                count += 1
                if count == 1:
                    continue
                device_mac = row[1]
                device_total_packet = int(row[2])
                device_suspicious_packet_num = int(row[3])
                device_suspicious_packet_num_endpoint_mismatch = int(row[4])
                suspicious_packet_num[device_mac] = device_suspicious_packet_num
                total_packets[device_mac] = device_total_packet
                suspicious_packet_num_endpoint_mismatch[device_mac] = device_suspicious_packet_num_endpoint_mismatch
        return suspicious_packet_num, suspicious_packet_num_endpoint_mismatch, total_packets

    def get_device_mac(self, packet, device_mac_list, packet_type):
        if packet_type == self.constant_values.PACKET_TYPE_CSV:
            src_mac = packet[5]
            destination_mac = packet[6]
        else:
            src_mac = self.get_source_mac_address(packet)
            destination_mac = self.get_destination_mac_address(packet)
        if src_mac in device_mac_list:
            device_mac = src_mac
        elif destination_mac in device_mac_list:
            device_mac = destination_mac
        else:
            device_mac_not_found_message = self.constant_values.DEVICE_MAC_NOT_FOUND_MESSAGE.format(src_mac, destination_mac )
            # print(device_mac_not_found_message)
            return
        return device_mac

    def get_packet_properties(self, packet, device_mac, packet_type):
        packet_direction = 'not determined'
        server_address = 'not determined'
        src_mac = self.get_source_mac_address(packet)
        destination_mac = self.get_destination_mac_address(packet)
        source_ip_address = self.get_source_ip_address(packet, packet_type, device_mac)
        destination_ip_address = self.get_destination_ip_address(packet, packet_type, device_mac)
        length = self.get_length(packet)
        if src_mac==device_mac:
            packet_direction = self.constant_values.PACKET_DIRECTION_DEVICE_TO_SERVER
            server_address = destination_ip_address
        elif destination_mac == device_mac:
            packet_direction = self.constant_values.PACKET_DIRECTION_SERVER_TO_DEVICE
            server_address = source_ip_address

        if source_ip_address.startswith(self.constant_values.LAN_ADDRESS_PREFIX) and destination_ip_address.startswith(
                self.constant_values.LAN_ADDRESS_PREFIX):
            if packet_direction == self.constant_values.PACKET_DIRECTION_DEVICE_TO_SERVER:
                packet_direction = self.constant_values.PACKET_DIRECTION_DEVICE_TO_USER
            else:
                packet_direction = self.constant_values.PACKET_DIRECTION_USER_TO_DEVICE
        return packet_direction, server_address, length, source_ip_address, destination_ip_address

    def get_packet_properties_csv(self, packet, device_mac, packet_type):
        src_mac = packet[5]
        destination_mac = packet[6]
        source_ip_address = self.get_source_ip_address(packet, packet_type, device_mac)
        destination_ip_address = self.get_destination_ip_address(packet, packet_type, device_mac)
        length = packet[4]
        if source_ip_address.startswith(self.constant_values.LAN_ADDRESS_PREFIX):
            source_address = src_mac
        else:
            source_address = source_ip_address
        if destination_ip_address.startswith(self.constant_values.LAN_ADDRESS_PREFIX):
            destination_address = destination_mac
        else:
            destination_address = destination_ip_address

        return source_address, destination_address, length, source_ip_address, destination_ip_address
    def match_packet(self, device_mac, packet_direction, server_address, length, device_profile_data, profile_end_points_map):
        key_device_profile = DeviceProfileData(device_mac, packet_direction, server_address, length)
        device_profile = device_profile_data.get(key_device_profile)
        profile_matched = False
        endpoints_matched = False
        if device_profile is None:
            # profile not found for exact address, direction and length, check if exact direction is available
            key_profile_endpoints = DeviceProfileEndPoints(device_mac, packet_direction)
            device_profile_end_points = profile_end_points_map.get(key_profile_endpoints)
            if device_profile_end_points is not None:
                # profile found for same direction, check if address can be fuzzy matched
                    for stored_address in device_profile_end_points.external_address_list:
                        if profile_matched:
                            break
                        server_address_tld = tldextract.extract(server_address).registered_domain
                        stored_address_tld = tldextract.extract(stored_address).registered_domain
                        if server_address_tld == stored_address_tld:
                            if SM(None, stored_address, server_address).ratio() >= self.constant_values.ALLOWED_PACKET_MATCHING_RATIO:
                                # endpoints fuzzy matched. if profile is not found that would be for length
                                endpoints_matched = True
                                key_device_profile = DeviceProfileData(device_mac, packet_direction, stored_address, length)
                                device_profile = device_profile_data.get(key_device_profile)
                                if device_profile is not None:
                                    profile_matched = True

        else:
            profile_matched = True
        if not endpoints_matched:
            suspicion_reason = self.constant_values.SUSPICION_REASON_ADDRESS
        else:
            suspicion_reason = self.constant_values.SUSPICION_REASON_PACKET_LENGTH
        return profile_matched, suspicion_reason

    def match_packet_CSV(self, device_mac, source_address, destination_address, length, device_profile_data, profile_end_points_map):
        key_device_profile = DeviceProfileDataCSV(device_mac, source_address, destination_address, length)
        device_profile = device_profile_data.get(key_device_profile)
        profile_matched = False
        endpoints_matched = False
        packet_end_point_info = EndPointInfo(device_mac, source_address, destination_address)
        device_profile_end_points = profile_end_points_map.get(device_mac)
        if device_profile is None:
            if device_profile_end_points is not None:
                if packet_end_point_info not in device_profile_end_points.end_point_list:
                # profile found for same direction, check if address can be fuzzy matched
                    for end_point in device_profile_end_points.end_point_list:
                        if profile_matched:
                            break
                        source_address_tld = tldextract.extract(source_address).registered_domain
                        endpoint_source_address_tld = tldextract.extract(end_point.source_address).registered_domain
                        destination_address_tld = tldextract.extract(destination_address).registered_domain
                        endpoint_destination_address_tld = tldextract.extract(end_point.destination_address).registered_domain

                        if source_address_tld == endpoint_source_address_tld and destination_address_tld == endpoint_destination_address_tld:
                            if SM(None, end_point.source_address, source_address).ratio() >= self.constant_values.ALLOWED_PACKET_MATCHING_RATIO and SM(
                                    None, end_point.destination_address, destination_address).ratio() >= self.constant_values.ALLOWED_PACKET_MATCHING_RATIO:
                                    # endpoints already fuzzy matched. If profile is not found, it would be for length
                                endpoints_matched = True
                                key_device_profile = DeviceProfileDataCSV(device_mac, end_point.source_address, end_point.destination_address, length)
                                device_profile = device_profile_data.get(key_device_profile)
                                if device_profile is not None:
                                    profile_matched = True
                else:
                    endpoints_matched = True
        else:
            profile_matched = True
        if not endpoints_matched:
            suspicion_reason = self.constant_values.SUSPICION_REASON_ADDRESS
        else:
            suspicion_reason = self.constant_values.SUSPICION_REASON_PACKET_LENGTH
        return profile_matched, suspicion_reason
