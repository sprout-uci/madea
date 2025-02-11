import base64
import os
import socket
import subprocess as sp
import sys
from logging.handlers import RotatingFileHandler
from os.path import exists
import datetime
import RPi.GPIO as GPIO
import json
import logging
from ecdsa import SigningKey, VerifyingKey, NIST384p

root_path = sys.argv[1]
ledPin = 40
GPIO.setmode(GPIO.BOARD)  # use P1 header pin numbering convention
GPIO.setup(ledPin, GPIO.OUT)   # led pin setup

UDP_IP = ''
UDP_PORT = 9000
sock = socket.socket(socket.AF_INET,  socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

verifying_key = VerifyingKey.from_string('PLACE_HOLDER', curve=NIST384p)

signing_key = SigningKey.from_string('PLACE_HOLDER', curve=NIST384p)

process_list_file_name = 'expected_processes.txt'
process_list_file_path = os.path.join(root_path, process_list_file_name)
get_process_list_command = 'sudo ps aux | less > {0}'
check_process_hash_command = 'sudo sha256sum --check {0} > {1}'
process_hash_line = '{0} {1}\n'
calculate_process_hash_command = 'sudo sha256sum {0} > {1}'
exe_path = '/proc/{0}/exe'
copy_exe_command = 'cp {0} {1}'
process_hash_map = dict()
malicious_process_exe_copy_location = 'malicious_exe'
malicious_process_exe_copy_location_path = os.path.join(root_path, malicious_process_exe_copy_location)

logger = logging.getLogger("Bulb Log")
logger.setLevel(logging.INFO)
log_path = os.path.join(root_path, 'log/RPi_smart_bulb.log')
handler = RotatingFileHandler(log_path, maxBytes=10000000, backupCount=10)
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

def verify_signature(message, base64_signature):
    base64_bytes = base64_signature.encode()
    signature = base64.b64decode(base64_bytes)
    return verifying_key.verify(signature, message.encode())

def create_signature(message):
    signature = signing_key.sign(message.encode())
    base64_bytes = base64.b64encode(signature)
    base64_signature = base64_bytes.decode()
    return base64_signature

def get_expected_processes():
    global process_hash_map
    with open(process_list_file_path) as f:
        lines = f.readlines()
        for line in lines:
            fields = line.split()
            hash = fields[0]
            process = ' '.join(fields[1:])
            process_hash_map[process] = hash

def save_expected_processes():
    lines = []
    for process, hash_val in process_hash_map.items():
        line = process_hash_line.format(hash_val, process)
        lines.append(line)
    with open(process_list_file_path, 'w') as f:
        f.writelines(lines)

def get_current_processes_hash():
    global process_exe_map
    date = datetime.datetime.now()
    timestamp_str = '{0}-{1}-{2}_{3}_{4}_{5}'.format(str(date.year), str(date.month),
                                                     str(date.day),
                                                     str(date.hour),
                                                     str(date.minute), str(date.second))
    current_processes_file_name = 'ProcessList/current_processes_{0}.txt'.format(timestamp_str)
    current_processes_hash_file_name = 'ProcessList/current_processes_hash_{0}.txt'.format(timestamp_str)
    get_processes_command = get_process_list_command.format(current_processes_file_name)
    pipe = sp.run([get_processes_command], shell=True, check=True)
    current_processes_file_path = os.path.join(root_path, current_processes_file_name)
    current_processes_hash_file_path = os.path.join(root_path, current_processes_hash_file_name)
    current_processes_exe = set()
    current_processes = set()
    current_processes_hash_map = dict()
    exe_process_map = dict()
    process_exe_map = dict()
    heading = True
    with open(current_processes_file_path) as f:
        lines = f.readlines()
        for line in lines:
            if heading == True:
                heading = False
                continue
            fields = line.split()
            process = ' '.join(fields[10:])
            if process.startswith('[') and process.endswith(']'):
                continue
            if 'ps aux' in process or 'less' in process:
                continue
            current_processes.add(process)
            pid = fields[1]
            process_exe = exe_path.format(pid)
            current_processes_exe.add(process_exe)
            exe_process_map[process_exe] = process
            process_exe_map[process] = process_exe
    processes_str = ' '.join(current_processes_exe)
    calculates_hash_command = calculate_process_hash_command.format(processes_str, current_processes_hash_file_path)
    try:
        pipe = sp.run([calculates_hash_command], shell=True, check=True)
    except:
        pass
    with open(current_processes_hash_file_path) as f:
        lines = f.readlines()
        for line in lines:
            fields = line.split()
            hash = fields[0]
            process_exe = fields[1]
            process = exe_process_map[process_exe]
            current_processes_hash_map[process]=hash
    return current_processes_hash_map

def attest_process():
    current_processes_hash_map = get_current_processes_hash()
    wrong_processes = dict()
    new_processes = dict()
    for process, hash in current_processes_hash_map.items():
        if process_hash_map.get(process) is None:
            new_processes[process] = hash
            copy_command = copy_exe_command.format(process_exe_map.get(process), malicious_process_exe_copy_location_path)
            pipe = sp.run([copy_command], shell=True, check=True)
        elif process_hash_map.get(process) != current_processes_hash_map[process]:
            wrong_processes[process] = hash
            copy_command = copy_exe_command.format(process_exe_map.get(process), malicious_process_exe_copy_location_path)
            pipe = sp.run([copy_command], shell=True, check=True)
    return new_processes, wrong_processes

if exists(process_list_file_path):
    get_expected_processes()
else:
    process_hash_map = get_current_processes_hash()
    save_expected_processes()

while True:
    message_bytes, address = sock.recvfrom(1024)  # buffer size is 1024 bytes
    message = message_bytes.decode('utf-8')
    logger.info("received message: %s" % message)
    request = message.split()
    print(request[0])
    response = {}
    led_status = GPIO.LOW
    if request[0] == 'turn_on':
        led_status = GPIO.HIGH
        GPIO.output(ledPin, GPIO.HIGH)
        response["status"] = "200"
        response["message"] = "Light bulb turned on."
        reply = json.dumps(response)
        logger.info(reply)
        reply_bytes = reply.encode()
        sock.sendto(reply_bytes, address)
    elif request[0] == 'turn_off':
        led_status = GPIO.LOW
        GPIO.output(ledPin, GPIO.LOW)
        response["status"] = "200"
        response["message"] = "Light bulb turned off."
        reply = json.dumps(response)
        logger.info(reply)
        reply_bytes = reply.encode()
        sock.sendto(reply_bytes, address)
    elif request[0] == 'attest':
        challenge = request[1]
        base64_signature = request[2]
        if verify_signature(challenge, base64_signature) is False:
            response["status"] = "401"
            response["error_message"] = "Authentication failed."
            reply = json.dumps(response)
            logger.info(reply)
            reply_bytes = reply.encode()
            sock.sendto(reply_bytes, address)
        else:
            new_processes, wrong_processes = attest_process()
            if len(wrong_processes)==0 and len(new_processes)==0:
                response["status"] = "200"
                response["message"] = "No change in processes. Device healthy."
                signature_message = response["status"] + challenge
                response["signature"] = create_signature(signature_message)
                reply = json.dumps(response)
                logger.info(reply)
                reply_bytes = reply.encode()
                sock.sendto(reply_bytes, address)
            else:
                response["status"] = "409"
                response["error_message"] = "Change in processes. Device unhealthy."
                signature_message = response["status"] + challenge
                response["signature"] = create_signature(signature_message)
                response['new_processes'] = new_processes
                response['wrong_processes'] = wrong_processes
                reply = json.dumps(response)
                logger.info(reply)
                reply_bytes = reply.encode()
                sock.sendto(reply_bytes, address)
    elif request[0] == 'status':
        response["status"] = "200"
        if led_status == GPIO.HIGH:
            response["message"] = "Light bulb is currently on."
        else:
            response["message"] = "Light bulb is currently off."
        reply = json.dumps(response)
        logger.info(reply)
        reply_bytes = reply.encode()
        sock.sendto(reply_bytes, address)