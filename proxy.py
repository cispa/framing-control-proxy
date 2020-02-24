from utils import get_browser_from_user_agent, parse_csp, parse_headers, csp_match
from interceptor import InterceptorV4, InterceptorV6
from urllib.parse import urlparse
import traceback
import argparse
import socket
import json
import os

request_to_response = dict()  # Dictionary to map requests to their responses.


def retrofit_headers(original_headers: dict, request_key: int) -> dict:
    """
    Retrofits the apparent security header to match the needs of the client

    :param original_headers: Dictionary of headers send by the Web application
    :param request_key: Key for the request_to_response dictionary
    :return: Dictionary of retrofitted headers
    """

    new_headers = original_headers.copy()
    # DEBUG DATA
    browser = get_browser_from_user_agent(request_to_response[request_key][0])
    new_headers[b'Debug-FrameProxy-Browser'] = json.dumps(browser).encode()
    new_headers[b'Debug-FrameProxy-Request'] = request_to_response[request_key][1]
    # Check for CSP and XFO header being present
    has_xfo = b'x-frame-options' in original_headers
    has_csp = b'content-security-policy' in original_headers
    # Extract XFO header
    xfo = None
    if has_xfo:
        xfo = original_headers[b'x-frame-options'].strip()
    # Extract frame-sncestors directive from CSP
    has_fa = False
    frame_ancestors = None
    if has_csp:
        csp = original_headers[b'content-security-policy']
        parsed_csp = parse_csp(csp)
        if b'frame-ancestors' in parsed_csp:
            has_fa = True
            frame_ancestors = parsed_csp[b'frame-ancestors']
    # If the ste deploys neither XFO nor CSP ...
    if not has_xfo and not has_fa:
        # ... we can not retrofit anything
        del request_to_response[request_key]
        return new_headers
    # If CSP frame-ancestors is present (no matter if XFO is present or not)
    if has_fa:
        # Retrofit CSP to XFO
        if frame_ancestors == {b"'none'"}:
            new_xfo = b'DENY'
        elif frame_ancestors == {b"'self'"}:
            new_xfo = b'SAMEORIGIN'
        else:
            referrer = request_to_response[request_key][2]
            if referrer is not None:
                requested_url = request_to_response[request_key][1]
                if csp_match(frame_ancestors, referrer, requested_url.decode()):
                    new_xfo = b'ALLOW-FROM ' + referrer
                else:
                    new_xfo = b'DENY'
            else:
                new_xfo = b'DENY'
        # Depending on XFO being deployed we overwrite it or add the new XFO header
        new_headers[b'x-frame-options'] = new_xfo
    # If we have XFO but no CSP frame-ancestors
    elif has_xfo and not has_fa:
        # Convert XFO to the corresponding frame-ancestors
        new_csp = b''
        xfo_headers = xfo.lower().split(b',')
        xfo_modes = list()
        xfo_values = list()
        for el in xfo_headers:
            tmp = el.strip().split()
            xfo_modes.append(tmp[0])
            xfo_values.append(tmp[1:])
        # Implementation as generalisation of table 7 from the paper
        if len(set(xfo_modes)) <= 1:
            if xfo_modes[0] == b'sameorigin':
                new_csp = b"frame-ancestors 'self'"
            elif xfo_modes[0] == b'deny':
                new_csp = b"frame-ancestors 'none'"
            elif xfo_modes[0] == b'allow-from':
                origins = set()
                for value in xfo_values:
                    for origin in value:
                        origins.add(urlparse(origin).netloc)
                if len(origins) == 1:
                    new_csp = b"frame-ancestors " + origins.pop()
                else:
                    new_csp = b"frame-ancestors 'none'"
            else:
                new_headers[b'Debug-FrameProxy-Error-MSG'] = b'Malformed XFO Header!'
                new_headers[b'Debug-FrameProxy-Error-Data'] = xfo
        else:
            if b'deny' in xfo_modes:
                new_csp = b"frame-ancestors 'none'"
            elif b'sameorigin' in xfo_modes:
                for i, x in enumerate(xfo_modes):
                    if x == b'allow-from':
                        for origin in xfo_values[i]:
                            if new_headers[b'host'] != urlparse(origin).netloc:
                                new_csp = b"frame-ancestors 'none'"
                                break
                        else:
                            new_csp = b"frame-ancestors 'self'"
                        if new_csp == b"frame-ancestors 'none'":
                            break
        # If we have converted something we either add it besides the current CSP or deploy a new one.
        if new_csp != b'':
            if has_csp:
                combined_header = new_headers[b'content-security-policy'] + b', ' + new_csp
                new_headers[b'content-security-policy'] = combined_header
            else:
                new_headers[b'content-security-policy'] = new_csp
    # Fallback case (Should not happen because all 4 cases are covert)
    else:
        new_headers[b'Debug-FrameProxy-Error-MSG'] = b'Should NEVER happen case!'
        new_headers[b'Debug-FrameProxy-Error-Data'] = b'XFO, CSP, FA = (%s, %s, %s)' % (has_xfo, has_csp, has_fa)
    # Remove request_key from dict and return new header dictionary
    del request_to_response[request_key]
    return new_headers


def proxy(data: bytes, sock: socket, from_client: bool) -> bytes:
    """
    Function that handles the requests that are passed to the proxy and changes the data / header on-the-fly.

    :param data: raw data e.g. "GET /index.html HTTP/1.1\r\n..."
    :param sock: the socket object for this connection
    :param from_client: True if traffic coming from client

    :return: raw (possible changed) data
    """

    try:
        request_key = sock.getpeername()[1]
        if from_client:
            data_split = data.split(b'\r\n\r\n')
            raw_head = data_split[0]
            headers = parse_headers(raw_head)
            request_to_response[request_key] = [None, None, None]
            if b'user-agent' in headers:
                request_to_response[request_key][0] = headers[b'user-agent']
            if b'host' in headers:
                requested = b'http://' + headers[b'host'] + raw_head.split(b'\r\n')[0].split()[1]
                request_to_response[request_key][1] = requested
            if b'referer' in headers:
                request_to_response[request_key][2] = headers[b'referer']
            return data
        else:
            if not data.startswith(b'HTTP'):
                return data
            data_split = data.split(b'\r\n\r\n')
            raw_head = data_split[0]
            raw_body = b'\r\n\r\n'.join(data_split[1:])
            headers = parse_headers(raw_head)
            if b'content-type' not in headers:
                return data
            if not headers[b'content-type'].lower().startswith(b'text/html'):
                return data
            new_headers = retrofit_headers(headers, request_key)
            raw_response_head = [raw_head.split(b'\r\n')[0]]
            for name, value in new_headers.items():
                raw_response_head.append(name + b': ' + value)
            raw_response_head = b'\r\n'.join(raw_response_head)
            return raw_response_head + b'\r\n\r\n' + raw_body
    except Exception as e:
        print('Unexpected Exception', e)
        traceback.print_exc()
    return data


def main():
    """
    The Main Function that starts the Proxy and sets the preferences.

    :return: Never
    """

    parser = argparse.ArgumentParser()

    parser.add_argument("ipv", help="IP version to be used [4 or 6]", type=int)
    parser.add_argument("port", help="Port of your Web App", type=int)

    parser.add_argument("-v", "--verbose", dest='verbose', default=False,
                        action='store_true', help="Show detailed output")
    parser.add_argument("-d", "--debug", dest='debug', default=False,
                        action='store_true', help="Show debugging information")

    if os.getuid() != 0:
        print("To intersect all HTTP traffic this program requires root privileges. Exiting ...")
        exit(-1)

    args = parser.parse_args()

    if args.ipv not in [4, 6]:
        print("Only IP version 4 or 6 are supported. Exiting ...")
        exit(-1)

    if args.port < 1 or args.port > 65535:
        print("Port Numbers below 1 or above 65535 are not possible. Exiting ...")
        exit(-1)

    if args.ipv == 4:
        i4 = InterceptorV4(proxy, args.verbose, args.debug)
        i4.new_proxy(args.port)
        try:
            i4.run()
        except KeyboardInterrupt:
            i4.shutdown()
    else:
        i6 = InterceptorV6(proxy, args.verbose, args.debug)
        i6.new_proxy(args.port)
        try:
            i6.run()
        except KeyboardInterrupt:
            i6.shutdown()


if __name__ == "__main__":
    main()
