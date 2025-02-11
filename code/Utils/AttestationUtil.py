import base64
import json

from Utils.ConstantValues import ConstantValues

import socket
from ecdsa import SigningKey, VerifyingKey, NIST384p
import random
class AttestationUtil:
    def __init__(self, logger):
        self.constant_values = ConstantValues()
        self.logger = logger
        self.signing_key = SigningKey.from_string('PLACE_HOLDER', curve=NIST384p)
        self.verifying_key = VerifyingKey.from_string('PLACE_HOLDER', curve=NIST384p)
    def get_challenge_signature(self):
        challenge = format(random.randint(0,4294967295),'032d')
        signature = self.signing_key.sign(challenge.encode())
        base64_bytes = base64.b64encode(signature)
        base64_signature = base64_bytes.decode()
        print("Challenge: ", challenge)
        print("Signature: ", base64_signature)
        return challenge, base64_signature

    def verify_signature(self, message, base64_signature):
        base64_bytes = base64_signature.encode()
        signature = base64.b64decode(base64_bytes)
        return self.verifying_key.verify(signature, message.encode())
    def call_attestation(self):
        infected = True
        device_ip = 'PLACE_HOLDER'
        device_port = 9000

        challenge, signature = self.get_challenge_signature()
        message = self.constant_values.DEVICE_ATTESTATION_COMMAND_TEMPLATE.format(challenge, signature)
        udp_client_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        udp_client_socket.settimeout(60)
        # Send to server using created UDP socket
        bytes_to_send = str.encode(message)

        device_address_port = (device_ip, device_port)

        udp_client_socket.sendto(bytes_to_send, device_address_port)
        message_from_device = ''
        try:
            result_from_device_bytes, client_address = udp_client_socket.recvfrom(self.constant_values.UDP_BUFFER_SIZE)
            result_from_device = result_from_device_bytes.decode()
            self.logger.info('Attestation result received from device: '+result_from_device+'\n\n')
            response = json.loads(result_from_device)
            signature_message = response["status"]+challenge
            signature_verification = self.verify_signature(signature_message, response["signature"])
            if signature_verification:
                self.logger.info('Signature Verification Successful')
            else:
                self.logger.error('Signature Verification Failed')
            if signature_verification and response["status"] == '200':
                infected = False
                message_from_device = response["message"]
            else:
                message_from_device = response["error_message"]
        except:
            print('timeout from RPi bulb')
            pass

        return infected, message_from_device

