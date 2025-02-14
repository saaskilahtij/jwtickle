"""
This module defines the JWTTokenParsed class, which is used to handle and manipulate JWT tokens.
It provides methods to encode and decode JWT token parts (header, payload, and signature) and 
to return the token in string format.
"""

import json
import base64
import binascii
import logging

logger = logging.getLogger(__name__)

class JWTToken:
    """
        Class to handle JWT tokens.
    """
    def __init__(self, header_decoded, payload_decoded, signature_b64):
        self.header_decoded = header_decoded
        self.payload_decoded = payload_decoded
        self.signature_b64 = signature_b64
        self.token_decoded = [json.dumps(header_decoded), json.dumps(payload_decoded)]

    def encode_part(self, part):
        """
            Encode a part of the JWT (header or payload).
        """
        part_json = json.dumps(part).encode('UTF-8')
        return base64.urlsafe_b64encode(part_json).decode('UTF-8').rstrip('=')

    def encoded_to_string(self):
        """
            Return the token in string format.
        """
        header = self.encode_part(self.header_decoded)
        payload = self.encode_part(self.payload_decoded)
        return f"{header}.{payload}.{self.signature_b64}"

    def decoded_to_string(self):
        """
            Return a decoded token in string format.
        """
        return '.'.join(self.token_decoded)

    def change_algorithm(self, new_algorithm):
        """
            Change the algorithm in the JWT header.
        """
        self.header_decoded['alg'] = new_algorithm
        self.token_decoded[0] = json.dumps(self.header_decoded)

    def change_type(self, new_type):
        """
            Change the type in the JWT header.
        """
        self.header_decoded['typ'] = new_type
        self.token_decoded[0] = json.dumps(self.header_decoded)
