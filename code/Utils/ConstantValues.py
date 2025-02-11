class ConstantValues:
    DNS_QUERY_RESPONSE_MISMATCH_ERROR = 'DNS query name and response name do not match. Query Name: {0}, Response ' \
                                        'Name: {1} '
    NO_DEVICE_PROFILE_AVAILABLE_ERROR = 'No device profile available to monitor'
    SUSPICIOUS_PACKET_WARNING = 'Suspicious packet found for the device mac: {0}! Reason: {1}. Packet Summary:\n ' \
                                'source ip: {2}, destination ip: {3}, length : {4}, protocol: {5}, time: {6}\n'
    BENIGN_PACKET_MESSAGE = 'Benign Packet! Matched with Profile::\n ' \
                                'Device Name: {0}, Packet Direction: {1}, External Address: {2}, Packet length : {3}\n'
    SUSPICION_REASON_ADDRESS = 'No matching found for Source address and/or Destination address.\n'
    SUSPICION_REASON_PACKET_LENGTH = 'Packet length mismatch'
    DNS_A_COMMON_PART = '{}: type A, class IN, addr '
    DNS_CNAME_COMMON_PART = 'type CNAME, class IN, cname '
    ETHER_HOST_PBF_FILTER_TEMPLATE = 'ether host {0}'
    ETHER_HOST_DISPLAY_FILTER_TEMPLATE = 'eth.addr == {0}'
    DNS_MAP_CSV_FILE_NAME = 'smart_home_dns_map.csv'
    DEVICE_PROFILE_CSV_FILE_NAME = 'smart_home_device_profiles.csv'
    MONITORING_STAT_COMBINED = 'smart_home_monitoring_combined_stat.csv'
    MONITORING_TIMING_STAT = 'smart_home_monitoring_timing_stat.csv'
    UDP_BUFFER_SIZE = 1024
    DEVICE_ATTESTATION_COMMAND_TEMPLATE = "attest {0} {1}"
    INFECTED_DEVICE_ERROR = 'Infected device found! Device mac: {0}! Error Message: {1}'
    ALLOWED_PACKET_MATCHING_RATIO = 0.8
    LAN_ADDRESS_PREFIX = 'PLACE_HOLDER'
    ROUTER_ADDRESS = 'PLACE_HOLDER'
    PACKET_DIRECTION_DEVICE_TO_SERVER = 'DEVICE_TO_SERVER'
    PACKET_DIRECTION_DEVICE_TO_DEVICE = 'DEVICE_TO_DEVICE'
    PACKET_DIRECTION_SERVER_TO_DEVICE = 'SERVER_TO_DEVICE'
    PACKET_DIRECTION_DEVICE_TO_USER = 'DEVICE_TO_USER'
    PACKET_DIRECTION_USER_TO_DEVICE = 'USER_TO_DEVICE'
    DEVICE_MAC_NAME_MAPPING_CSV_FILE = 'Device_MAC_Name_Mapping.csv'
    PROFILING_DEVICE_MAC_LIST_CSV_FILE = 'Profiling_Device_MAC_List.csv'
    MONITORING_DEVICE_MAC_LIST_CSV_FILE = 'Monitoring_Device_MAC_List.csv'
    DEVICE_NAME_MAC_MAPPING_CSV_FILE = 'Device_Name_MAC_Mapping.csv'
    PACKET_TYPE_CSV = 'CSV'
    PACKET_TYPE_PCAP = 'PCAP'
    DEVICE_MAC_NOT_FOUND_MESSAGE = 'No device mac found! source mac: {1}, destination mac: {2}\n'
    PROFILE_COUNT_CSV_FILE_NAME_PROFILING = 'smart_home_profile_entries_count_profiling.csv'
    PROFILE_COUNT_CSV_FILE_NAME_MONITORING = 'smart_home_profile_entries_count_monitoring.csv'
    PROFILE_STATISTICS_CSV_FILE_NAME = 'smart_home_profile_statistics.csv'
    PROFILE_DETAILS_STATISTICS_CSV_FILE_NAME = 'smart_home_profile_details_statistics.csv'
    PROFILE_DETAILS_ENDPOINT_CSV_FILE_NAME = 'smart_home_profile_details_endpoints_statistics.csv'
    SYSTEM_OPERATION_PROFILING = 'profiling'
    SYSTEM_OPERATION_MONITORING = 'monitoring'

