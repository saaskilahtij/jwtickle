"""
Author: Johan Sääskilahti
Description: The tool to use when you want to tickle the security of JWTs.
"""
import argparse
import json
import base64
import binascii
from .jwt_token import JWTToken

DESC = r"""
        JWTickle is a tool to tickle the security of JWTs.
"""

def args_parser():
    """
        Parse the arguments provided by the user.
    """
    parser = argparse.ArgumentParser(description=DESC, prog='jwtickle.py',
                                    formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-t', '--token', type=str, help='JWT as a string')
    parser.add_argument('-f', '--file', type=str, help='file containing JWTs')
    parser.add_argument('-n', '--none', action='store_true', help='print token with none algorithm')
    args = parser.parse_args()
    if args.token and args.file:
        parser.error("do not pass both arguments -t/--token and -f/--file")
    if not args.token and not args.file:
        parser.error("one of the arguments -t/--token or -f/--file must be provided")
    return args

def add_padding(base64_string):
    """
        Add padding to the base64 string.
    """
    return base64_string + '=' * (-len(base64_string) % 4)

def jwt_parse(jwt_token):
    """
        Parse the JWT token.
        If signature is not present, sets it to None
        Args:
            Raw token as a string
        Returns:
            JWTToken object
    """
    # Check if the token is correctly formatted
    if jwt_token.count('.') < 2:
        print("Are JWT tokens correctly formatted?")
        return None

    try:
        jwt_token_encoded = jwt_token.split('.')
        header_b64 = add_padding(jwt_token_encoded[0])
        payload_b64 = add_padding(jwt_token_encoded[1])
        signature_b64 = jwt_token_encoded[2] if len(jwt_token_encoded) > 2 else None
        header = json.loads(base64.urlsafe_b64decode(header_b64).decode('UTF-8'))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('UTF-8'))
    except (binascii.Error, json.JSONDecodeError) as e:
        print(f'Error: "{e}" while parsing JWT token')
        print("Are JWT tokens correctly formatted?")
        return None

    return JWTToken(header, payload, signature_b64)  # Update return value

def main():
    """
        Main function of the program.
    """
    args = args_parser()

    jwt_list_parsed = []

    if args.token:
        jwt_list_parsed.append(jwt_parse(args.token))
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            tokens = f.readlines()
            for token in tokens:
                parsed_token = jwt_parse(token.strip())
                jwt_list_parsed.append(parsed_token)
    else:
        print('No JWTs provided.')

    if args.none:
        for jwt_token in jwt_list_parsed:
            jwt_token.change_algorithm('none')
            print(jwt_token.encoded_to_string())
    else:
        for jwt_token in jwt_list_parsed:
            for part in jwt_token.token_decoded:
                print(part)
            print()

if __name__ == '__main__':
    main()
