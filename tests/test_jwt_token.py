"""
This module contains unit tests for the JWTToken class in the jwtickle library.

The tests cover the following functionalities:
- Initialization of the JWTToken object.
- Encoding and decoding of JWT tokens to and from strings.
- Changing the algorithm and type in the JWT header.
"""

import json
from source.jwtickle import JWTToken

def test_jwt_token_parsed_initialization():
    """
    Test the initialization of the JWTToken object.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    signature = "signature"

    jwt_token = JWTToken(header, payload, signature)

    assert jwt_token.header_decoded == header
    assert jwt_token.payload_decoded == payload
    assert jwt_token.signature_b64 == signature
    assert jwt_token.token_decoded == [json.dumps(header), json.dumps(payload)]

def test_jwt_token_parsed_encoded_to_string():
    """
    Test the encoded_to_string method of JWTToken.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    signature = "signature"

    jwt_token = JWTToken(header, payload, signature)
    encoded_token = jwt_token.encoded_to_string()

    fstring = f"{jwt_token.encode_part(header)}.{jwt_token.encode_part(payload)}.{signature}"

    assert encoded_token == fstring

def test_jwt_token_parsed_decoded_to_string():
    """
    Test the decoded_to_string method of JWTToken.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    signature = "signature"

    jwt_token = JWTToken(header, payload, signature)
    decoded_token = jwt_token.decoded_to_string()

    assert decoded_token == f"{json.dumps(header)}.{json.dumps(payload)}"

def test_jwt_token_parsed_change_algorithm():
    """
    Test changing the algorithm in the JWT header.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    signature = "signature"

    jwt_token = JWTToken(header, payload, signature)
    jwt_token.change_algorithm("none")

    assert jwt_token.header_decoded["alg"] == "none"

def test_jwt_token_parsed_change_type():
    """
    Test changing the type in the JWT header.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    signature = "signature"

    jwt_token = JWTToken(header, payload, signature)
    jwt_token.change_type("TEST")

    assert jwt_token.header_decoded["typ"] == "TEST"
