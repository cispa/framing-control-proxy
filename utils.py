from tldextract import tldextract
import re


def parse_headers(raw_head: bytes) -> dict:
    """
    Parses the raw request / response head into a dictionary of headers.
    Returns the dictionary with header name as key and header value as value.

    :param raw_head:bytes
    :return: headers:dict
    """

    headers = dict()
    for line in raw_head.split(b'\r\n'):
        try:
            i = line.index(b':')
            name = line[:i].strip().lower()
            value = line[i + 1:].strip()
            headers[name] = value
        except ValueError:
            continue

    return headers


def parse_csp(csp_string: bytes) -> dict:
    """
    Parses the CSP string according to the 2.2. Policies standard
    Returns the CSP as dictionary with directive as key and set of source-expressions as value.

    :param csp_string:string
    :return: csp_dict:dict
    """

    # Let policy be a new policy with an empty directive set
    complete_policy = {}
    # For each token returned by splitting list on commas
    for policy_string in csp_string.lower().split(b','):
        # Let policy be a new policy with an empty directive set
        policy = dict()
        # For each token returned by strictly splitting serialized on the U+003B SEMICOLON character (;):
        tokens = policy_string.split(b';')
        for token in tokens:
            # Strip all leading and trailing ASCII whitespace from token.
            data = token.strip().split()
            # If token is an empty string, continue.
            if len(data) == 0:
                continue
            # Let directive name be the result of collecting a sequence of code points from
            # token which are not ASCII whitespace.
            while data[0] == ' ':
                data = data[1:]
                if len(data) == 0:
                    break
            # If token is an empty string, continue.
            if len(data) == 0:
                continue
            # Set directive name to be the result of running ASCII lowercase on directive name.
            directive_name = data[0]
            # If policy's directive set contains a directive whose name is directive name, continue.
            if directive_name in policy:
                continue
            # Let directive value be the result of splitting token on ASCII whitespace.
            directive_set = set()
            for d in data[1:]:
                if d.strip() != '':
                    directive_set.add(d)
            # Append directive to policy’s directive set.
            policy[directive_name] = directive_set
        for name in policy:
            if name in complete_policy:
                if complete_policy[name] != policy[name]:
                    inter_sec = complete_policy[name].intersection(policy[name])
                    complete_policy[name] = inter_sec
                    continue
            complete_policy[name] = policy[name]
    # Return policy.
    return complete_policy


def csp_match(frame_ancestors: set, referrer: bytes, accessed_url: str) -> bool:
    """
    Checks if the referrer matches one of the frame-ancestors entries.
    Returns True if CSP matches and False if not.

    :param frame_ancestors:set
    :param referrer:bytes
    :param accessed_url:str
    :return: match:bool
    """

    referer_dom = tldextract.extract(referrer.decode())
    for source in frame_ancestors:
        if source == referrer:
            return True
        if source.startswith(b'/') and source in [b'https:', b'http:', b'https://*', b'http://*']:
            return True
        source_dom = tldextract.extract(source.decode())
        if source_dom.suffix != '' and source_dom.subdomain != '':  # If there is a sub domain ...
            if source_dom.subdomain.startswith('*'):  # eg. *.google.com or *.subn. ... .sub1.google.com
                c_sub = '.'.join(p for p in referer_dom if p)
                match = c_sub[2:] in '.'.join(p for p in referer_dom if p)
                if match:
                    return True
                continue
            else:  # eg. sub.google.com or subn. ... .sub1.google.com
                match = '.'.join(p for p in source_dom if p) == '.'.join(p for p in referer_dom if p)
                if match:
                    return True
                continue
        elif source_dom.suffix != '' and source_dom.domain != '':  # eg. google.com
            match = '.'.join(p for p in source_dom[1:] if p) == '.'.join(p for p in referer_dom[1:] if p)
            if match:
                return True
            continue
        elif source.endswith(b':') or source.endswith(b'://*'):  # eg. https:, https://*, ....
            match = referrer.startswith(source.replace(b'*', b''))
            if match:
                return True
            continue
        elif source.startswith(b"'"):  # eg. 'self', 'none'
            if source == b"'self'":
                accessed_dom = tldextract.extract(accessed_url)
                match = '.'.join(accessed_dom) == '.'.join(referer_dom)
                if match:
                    return True
            continue
        elif source.strip() == b'*':  # If allow all traffic
            return True
        elif re.match(r'\d*\.\d*\.\d*\.\d*', source_dom.domain):  # If cs is IP address
            match = source_dom.domain == referer_dom.domain
            if match:
                return True
            continue
        else:  # Debug message
            print('Failed to process:', source)
    return False


def get_browser_from_user_agent(user_agent: bytes) -> dict:
    """
    Translates the raw user-agent string into the browser name and version
    Returns a dictionary with name and version of the browser

    :param user_agent:bytes
    :return: browser:dict
    """

    user_agent = user_agent.decode().lower()

    x = re.findall(r'(opera|chrome|safari|firefox|msie|trident(?=/))/?\s*(\d+)', user_agent)[0]
    m = list()
    m.append(x[0] + '/' + x[1])
    m.append(x[0])
    m.append(x[1])

    if re.match(r'trident', m[1]):
        ver = re.match(r'\brv[ :]+(\d+)', user_agent)
        ver = ver[1] if len(list(ver)) > 1 else ''
        return {
            'name': 'ie',
            'version': ver
        }

    if m[1] == 'chrome':
        is_opera = re.match(r'\bOPR|Edge/(\d+)', m[1])
        if is_opera:
            return {
                'name': 'opera',
                'version': is_opera[1]
            }

    if len(m) > 2:
        m = [m[1], m[2]]
    else:
        app_data = user_agent.split('/')
        m = [app_data[0], '/'.join(app_data[1:]), '-?']

    version_info = re.match(r'version/(\d+)i', user_agent)
    if version_info:
        m[1] = version_info[1]

    return {
        'name': m[0],
        'version': m[1]
    }
