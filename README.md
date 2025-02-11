# Data Set

The `dataset` folder contains the pcap files collected from smart home setup to train and evaluate MADEA.

# Source Code

The `code` folder contains the source code.

# To Run the Code

- Install packages: `pyshark`, `ecdsa`, `dns`, `tldextract`

- Inside code folder, create new folders:
  - `log`
  - `traffic`
  - `traffic/training`
  - `traffic/monitoring`

- If necessary, change the network interface name in line 198 of `NetworkMonitor.py` and line 136 of `ProfileBuilder.py`

- Create CSV files:
  - `Device_MAC_Name_Mapping.csv` - Contains information for all IoT devices in the system.
    - Headers: MAC Address, Device Name
  - `Profiling_Device_MAC_List.csv` - List for devices that need to be trained. No header.
  - `Monitoring_Device_MAC_List.csv` - List for devices that need to be monitored. No header.

### For live capture, use the commands:
```console
python3 ProfileBuilder.py "complete project path" False PCAP
python3 NetworkMonitor.py "complete project path" False PCAP
```
### For offline pcap files:
- Put training files inside `traffic/training` folder
- Put monitoring files inside `traffic/monitoring` folder
- Use the commands:
```console
python3 ProfileBuilder.py "complete project path" True PCAP
python3 NetworkMonitor.py "complete project path" True PCAP
```
