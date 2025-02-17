"""
Author: Johan Sääskilahti
Description: The tool to use when you want to tickle the security of JWTs.
"""
import argparse
import json
import base64
import logging
import requests
from jwt_token import JWTToken
logger = logging.getLogger(__name__)

# Add tests for printing the encoded and decoded JWTTokens

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
    parser.add_argument('-f', '--file', type=str, help='file containing a JWT')
    parser.add_argument('-n', '--none', action='store_true', help='use none algorithm')
    parser.add_argument('-r', '--request', type=str, help='make a request with a curl txt file')
    parser.add_argument('--pd', '--print-decoded', action='store_true' ,
                        help='print the decoded JWToken')
    parser.add_argument('--pe', '--print-encoded', action='store_true',
                        help="print the encoded JWToken")
    args = parser.parse_args()
    if args.token and args.file:
        parser.error("[-] do not pass both arguments -t/--token and -f/--file")
    if not args.token and not args.file:
        parser.error("[-] one of the arguments -t/--token or -f/--file must be provided")
    return args

def padding_add(base64_string):
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
        logger.error("[-] Error: JWT token count is less than 2")
        logger.error("Is the JWT token correctly formatted?")
        return None

    try:
        jwt_token_encoded = jwt_token.split('.')
        header_b64 = padding_add(jwt_token_encoded[0])
        payload_b64 = padding_add(jwt_token_encoded[1])
        signature_b64 = jwt_token_encoded[2] if len(jwt_token_encoded) > 2 else None
        header = json.loads(base64.urlsafe_b64decode(header_b64).decode('UTF-8'))
        payload = json.loads(base64.urlsafe_b64decode(payload_b64).decode('UTF-8'))
    except (json.JSONDecodeError) as e:
        raise Exception(f"Error while parsing JWT token: {e}") from e

    return JWTToken(header, payload, signature_b64)

def parse_raw_request(file):
    """
        Parse the raw request from a file. Totally legit and solid parser :D
        Args:
            file: file containing the raw request
        Returns:
            Parsed request as a dictionary
    """
    request = []
    header_list = []
    request_parsed = {}
    try:
        with open(file, 'r', encoding='utf-8') as f:
            request = f.readlines()
    except Exception as e:
        raise Exception("Error while reading the file") from e

    # Parse method, URL and HTTP version
    try:
        request_parsed['method'] = request[0].split(' ')[0]
        request_parsed['url'] = request[0].split(' ')[1]
        request_parsed['http_version'] = request[0].split(' ')[2].strip()
    except:
        raise Exception("Error while parsing method, URL and HTTP version")

    # Parse rest of the headers
    for i in range(1, len(request)):
        if request[i] != '\n':
            header_list.append(request[i].strip('\n').split())

    # Add headers to the dictionary for easier access
    for i in range(len(header_list)):
        if header_list[i] != '':
            request_parsed[header_list[i][0].strip(':')] = header_list[i][1]

    return request_parsed

def main():
    """
        Main function of the program.
    """
    args = args_parser()
    jwt_parsed = ''

    if args.token:
        jwt_parsed = jwt_parse(args.token)
    elif args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            jwt_parsed = jwt_parse(f.readline())
        f.close()
    else:
        logger.error('[-] No JWT provided.')

    if args.none:
        jwt_parsed.change_algorithm('none')

    if args.pd:
        print(jwt_parsed.decoded_to_string())

    if args.pe:
        print(jwt_parsed.encoded_to_string())

    if args.request:
        parsed_request = parse_raw_request(args.request)
        headers = {}

        for header, value in list(parsed_request.items())[3:]:
            headers[header] = value
            s = requests.Session()

        if parsed_request['method'] == 'GET':
            try:
                res = s.get(parsed_request['url'], headers=headers)
                print(f'[+] Response status code: {res.status_code}')
            except requests.exceptions.InvalidSchema as exc:
                raise Exception("Error while sending GET request") from exc
        else:
            logger.error('[-] Method not supported')

if __name__ == '__main__':
    main()
