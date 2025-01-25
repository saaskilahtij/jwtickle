"""
This module contains unit tests for the jwtickle library.

The tests cover the following functionalities:
- Argument parsing with no arguments, token argument, file argument, and both arguments.
- Parsing of JWT tokens.
- Encoding and decoding of JWT tokens to and from strings.

These tests are a work in progress. Gently ignore them.
"""
import sys
import json
import base64
import pytest
from source.jwtickle import args_parser, jwt_parse

def test_no_arguments():
    """
    Test that the program exits when no arguments are provided.
    """
    test_args = ['jwtickle.py']
    sys.argv = test_args
    with pytest.raises(SystemExit):
        args_parser()

def test_token_argument():
    """
    Test that the program accepts the token argument.
    TODO: Test the validity of the token.
    """
    test_args = ['jwtickle.py', '-t', 'test_token']
    sys.argv = test_args
    args = args_parser()
    assert args.token == 'test_token'
    assert args.file is None

def test_file_argument():
    """
    Test that the program accepts the file argument.
    TODO: Test the validity of all the tokens.
    """
    test_args = ['jwtickle.py', '-f', 'test_file']
    sys.argv = test_args
    args = args_parser()
    assert args.file == 'test_file'
    assert args.token is None

def test_both_arguments():
    """
    Test that the program exits when both arguments are provided.
    """
    test_args = ['jwtickle.py', '-t', 'test_token', '-f', 'test_file']
    sys.argv = test_args
    with pytest.raises(SystemExit):
        args_parser()

def test_jwtickle_parse():
    """
    Test the jwt_parse function.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    signature = "signature"
    formatted_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
    formatted_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    token = f"{formatted_header}.{formatted_payload}.{signature}"

    parsed_token = jwt_parse(token)

    assert parsed_token.header_decoded == header
    assert parsed_token.payload_decoded == payload
    assert parsed_token.signature_b64 == signature

def test_jwtickle_encoded_to_string():
    """
    Test the encoded_to_string method.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    signature = "signature"
    formatted_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
    formatted_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    token = f"{formatted_header}.{formatted_payload}.{signature}"

    parsed_token = jwt_parse(token)
    encoded_token = parsed_token.encoded_to_string()

    assert encoded_token == token

def test_jwtickle_decoded_to_string():
    """
    Test the decoded_to_string method.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
    signature = "signature"
    formatted_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode()
    formatted_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    token = f"{formatted_header}.{formatted_payload}.{signature}"

    parsed_token = jwt_parse(token)
    decoded_token = parsed_token.decoded_to_string()

    assert decoded_token == f"{json.dumps(header)}.{json.dumps(payload)}"
