import csv
import datetime
import logging
import os
from logging.handlers import RotatingFileHandler
from os.path import exists
import pyshark
import asyncio
import sys

from Analysis.DeviceProfileData import DeviceProfileData
from Analysis.DeviceProfileDataCSV import DeviceProfileDataCSV
from Analysis.DeviceProfileEndPoints import DeviceProfileEndPoints
from Analysis.DeviceProfileEndPointsCSV import DeviceProfileEndPointsCSV
from Analysis.EndPointInfo import EndPointInfo
from Utils.ConstantValues import ConstantValues
from Utils.DnsUtil import DnsUtil
from Utils.PacketUtil import PacketUtil

root_path = sys.argv[1]
if sys.argv[2] == 'True':
    offline_capture = True
else:
    offline_capture = False
file_type = sys.argv[3]
global_device_mac = None
if len(sys.argv)==5:
    global_device_mac = sys.argv[4]
constant_values = ConstantValues()
dns_util = DnsUtil(root_path)
packet_util = PacketUtil(dns_util)
device_profile_data = dict()
new_profile_data = dict()
profile_end_points_map = dict()
device_mac_name_mapping = dict()
device_packet_num = dict()
logger = logging.getLogger("Training Log")
logger.setLevel(logging.INFO)

log_path = os.path.join(root_path, 'log/smart_home_training.log')
handler = RotatingFileHandler(log_path, maxBytes=10000000,
                              backupCount=10)
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
def process_packets(packet, packet_type = constant_values.PACKET_TYPE_PCAP):
    global device_profile_data, profile_end_points_map, new_profile_data
    try:
        if packet_util.is_configuration_packet(packet, packet_type):
            return
        if packet_type == constant_values.PACKET_TYPE_PCAP and not packet_util.is_ip_packet(packet):
            return
        if global_device_mac is None:
            device_mac = packet_util.get_device_mac(packet, device_mac_list, packet_type)
        else:
            device_mac = global_device_mac
        if device_mac is None:
            return
        if packet_type == constant_values.PACKET_TYPE_PCAP:
            if packet_util.is_dns_response_packet(packet):
                dns_util.process_dns_packet(packet, device_mac)
                return
            packet_direction, server_address, length, source_ip_address, destination_ip_address = packet_util.get_packet_properties(packet, device_mac, packet_type)
            profile_matched, suspicion_reason = packet_util.match_packet(device_mac, packet_direction, server_address, length, device_profile_data, profile_end_points_map)
        else:
            source_address, destination_address, length, source_ip_address, destination_ip_address = packet_util.get_packet_properties_csv(
                packet, device_mac, packet_type)
            profile_matched, suspicion_reason = packet_util.match_packet_CSV(device_mac, source_address, destination_address,
                                                                         length, device_profile_data,
                                                                         profile_end_points_map)
        packet_num = device_packet_num.get(device_mac)
        if packet_num is None:
            packet_num = 1
        else:
            packet_num += 1
        device_packet_num[device_mac] = packet_num
        if not profile_matched:
            device_name = device_mac_name_mapping.get(device_mac)
            if packet_type == constant_values.PACKET_TYPE_PCAP:
                key_device_profile = DeviceProfileData(device_mac, packet_direction, server_address, length)
                new_device_profile = DeviceProfileData(device_mac, packet_direction, server_address, length, device_name)
                key_profile_endpoints = DeviceProfileEndPoints(device_mac, packet_direction)
                device_profile_end_points = profile_end_points_map.get(key_profile_endpoints)
                if device_profile_end_points is None:
                    device_profile_end_points = DeviceProfileEndPoints(device_mac, packet_direction)
                device_profile_end_points.external_address_list.add(server_address)
                profile_end_points_map[key_profile_endpoints] = device_profile_end_points
            else:
                key_device_profile = DeviceProfileDataCSV(device_mac, source_address, destination_address, length)
                new_device_profile = DeviceProfileDataCSV(device_mac, source_address, destination_address, length, device_name)
                end_point_info = EndPointInfo(device_mac, source_address, destination_address)
                device_profile_end_points = profile_end_points_map.get(device_mac)
                if device_profile_end_points is None:
                    device_profile_end_points = DeviceProfileEndPointsCSV(device_mac)
                device_profile_end_points.end_point_list.add(end_point_info)
                profile_end_points_map[device_mac] = device_profile_end_points

            device_profile_data[key_device_profile] = new_device_profile
            new_profile_data[key_device_profile] = new_device_profile
    except AttributeError:
        pass


def capture_packets(packet_count=0, input_file_name=None):
    global device_profile_data, file_type

    try:
        if offline_capture:
            if file_type == constant_values.PACKET_TYPE_PCAP:
                packet_filter = constant_values.ETHER_HOST_DISPLAY_FILTER_TEMPLATE.format(device_mac_list[0])
                for i in range(1, len(device_mac_list)):
                    packet_filter_i = constant_values.ETHER_HOST_DISPLAY_FILTER_TEMPLATE.format(device_mac_list[i])
                    packet_filter = packet_filter + ' or ' + packet_filter_i
                capture = pyshark.FileCapture(input_file_name, display_filter=packet_filter)
                capture.apply_on_packets(process_packets, packet_count=packet_count)
            if file_type == constant_values.PACKET_TYPE_CSV:
                with open(input_file_name, 'r', encoding='UTF8', newline='') as f:
                    reader = csv.reader(f)
                    count = 0
                    for row in reader:
                        count += 1
                        if count == 1:
                            continue
                        process_packets(row, constant_values.PACKET_TYPE_CSV)
        else:
            date = datetime.datetime.now()
            file = "traffic/training_{0}-{1}-{2}_{3}_{4}_{5}.cap".format(
                str(date.year), str(date.month), str(date.day), str(date.hour), str(date.minute),
                str(date.second))
            file_path = os.path.join(root_path, file)

            packet_filter = constant_values.ETHER_HOST_PBF_FILTER_TEMPLATE.format(device_mac_list[0])
            for i in range(1, len(device_mac_list)):
                packet_filter_i = constant_values.ETHER_HOST_PBF_FILTER_TEMPLATE.format(device_mac_list[i])
                packet_filter = packet_filter + ' or ' + packet_filter_i
            capture = pyshark.LiveCapture(output_file=file_path, bpf_filter=packet_filter, interface='wlan0')
            capture.apply_on_packets(process_packets, packet_count=packet_count)
    except asyncio.TimeoutError as error:
        print(error)
        pass
    finally:
        if file_type == constant_values.PACKET_TYPE_PCAP:
            packet_util.save_device_profiles_to_csv(new_profile_data, device_packet_num, root_path, constant_values.SYSTEM_OPERATION_PROFILING)
        else:
            packet_util.save_csv_device_profiles_to_csv(new_profile_data, device_packet_num, root_path,
                                                        constant_values.SYSTEM_OPERATION_PROFILING)

        dns_util.save_dns_map_to_csv(root_path)


if offline_capture:
    path = 'traffic/training'
    traffic_path = os.path.join(root_path, path)
    file_list=os.listdir(traffic_path)
    list_of_files = []
    device_mac_list = packet_util.get_device_mac_list(root_path, constant_values.SYSTEM_OPERATION_PROFILING)

    if exists(os.path.join(root_path, constant_values.DEVICE_PROFILE_CSV_FILE_NAME)):
        if file_type == constant_values.PACKET_TYPE_PCAP:
            device_profile_data, profile_end_points_map = packet_util.get_existing_device_profiles(
                root_path)
        else:
            device_profile_data, profile_end_points_map = packet_util.get_existing_csv_device_profiles(
                root_path)
    if exists(os.path.join(root_path, constant_values.DEVICE_MAC_NAME_MAPPING_CSV_FILE)):
        device_mac_name_mapping = packet_util.get_device_mac_name_mapping(root_path)

    for file in file_list:
        list_of_files.append(os.path.join(traffic_path, file))
    for input_file in list_of_files:
        new_profile_data.clear()
        logger.info('File Name: ' + input_file)
        print(input_file)
        capture_packets(20000, input_file)

else:
    while True:
        new_profile_data.clear()
        device_mac_list = packet_util.get_device_mac_list(root_path, constant_values.SYSTEM_OPERATION_PROFILING)

        if exists(os.path.join(root_path, constant_values.DEVICE_PROFILE_CSV_FILE_NAME)):
            if file_type == constant_values.PACKET_TYPE_PCAP:
                device_profile_data, profile_end_points_map = packet_util.get_existing_device_profiles(
                    root_path)
            else:
                device_profile_data, profile_end_points_map = packet_util.get_existing_csv_device_profiles(
                    root_path)
        if exists(os.path.join(root_path, constant_values.DEVICE_MAC_NAME_MAPPING_CSV_FILE)):
            device_mac_name_mapping = packet_util.get_device_mac_name_mapping(root_path)
        capture_packets(20000)
