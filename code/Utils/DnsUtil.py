import csv
import os
from os.path import exists

import dns.resolver

from Analysis.DeviceIpMapping import DeviceIpMapping
from Utils.ConstantValues import ConstantValues


class DnsUtil:
    def __init__(self, root_path):
        self.ip_host_name_map = dict()
        self.no_reverse_lookup = set()
        self.constant_values = ConstantValues()
        dns_path = os.path.join(root_path,self.constant_values.DNS_MAP_CSV_FILE_NAME)
        if exists(dns_path):
            with open(dns_path, 'r', encoding='UTF8', newline='') as f:
                reader = csv.reader(f)
                count = 0
                for row in reader:
                    count += 1
                    if count == 1:
                        continue
                    device_mac = row[0]
                    ip_address = row[1]
                    host_name = row[2]
                    device_ip_mapping = DeviceIpMapping(device_mac, ip_address)
                    self.ip_host_name_map[device_ip_mapping] = host_name


    def get_host_address(self, ip_address, device_mac):
        device_ip_mapping = DeviceIpMapping(device_mac, ip_address)
        host_address = self.ip_host_name_map.get(device_ip_mapping)
        if host_address is None:
            host_address = ip_address
            # perform reverse dns lookup
            if ip_address not in self.no_reverse_lookup:
                try:
                    qname = dns.reversename.from_address(ip_address)
                    answer = dns.resolver.resolve(qname, 'PTR')
                    host_address = str(answer[0]).strip().rstrip('.')
                    self.ip_host_name_map[device_ip_mapping] = host_address
                except Exception:
                    self.no_reverse_lookup.add(ip_address)
                    pass
        return host_address

    def process_dns_packet(self, packet, device_mac):
        query_name = packet.dns.qry_name
        response_name = packet.dns.resp_name
        if not query_name == response_name:
            print(self.constant_values.DNS_QUERY_RESPONSE_MISMATCH_ERROR.format(query_name, response_name))
        dns_str = str(packet.dns)
        answer_index = dns_str.find('Answers')
        answer_index = answer_index+len('Answers')
        name_server_index = dns_str.find('Authoritative nameservers')
        address_substring = dns_str[answer_index:name_server_index]
        address_lines = address_substring.split('\n')
        entry_name=query_name

        for line in address_lines:
            line_a_common_part = self.constant_values.DNS_A_COMMON_PART.format(entry_name)
            address_index_start = line.find(line_a_common_part)
            if address_index_start !=-1:
                address_index_start = address_index_start + len(line_a_common_part)
                ip_address = line[address_index_start:]
                ip_address = ip_address.strip()
                device_ip_mapping = DeviceIpMapping(device_mac, ip_address)
                self.ip_host_name_map[device_ip_mapping]=query_name
            else:
                line_cname_common_part = self.constant_values.DNS_CNAME_COMMON_PART.format(entry_name)
                cname_index_start = line.find(line_cname_common_part)
                if cname_index_start !=-1:
                    cname_index_start = cname_index_start + len(line_cname_common_part)
                    cname = line[cname_index_start:]
                    cname = cname.strip()
                    entry_name = cname

    def save_dns_map_to_csv(self, root_path):
        dns_map_csv_header = ['DEVICE_MAC','IP_ADDRESS','HOST_NAME']
        dns_map_path = os.path.join(root_path,self.constant_values.DNS_MAP_CSV_FILE_NAME)
        with open(dns_map_path, 'w', encoding='UTF8', newline='') as f:
            writer = csv.writer(f)
            # write the header
            writer.writerow(dns_map_csv_header)
            for device_ip_mapping, host_name in self.ip_host_name_map.items():
                row_value = [device_ip_mapping.device_mac, device_ip_mapping.ip_address, host_name]
                writer.writerow(row_value)


    def add_new_dns_entry(self, device_mac, ip_address, host_name):
        device_ip_mapping = DeviceIpMapping(device_mac, ip_address)
        self.ip_host_name_map[device_ip_mapping] = host_name

