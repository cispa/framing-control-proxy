### Usage:
python3 proxy.py <ip_version> <web_application_port>

### Description:

The implementation of our proxy is split into three files. In `interceptor.py`, we implemented the intersection of traffic that is exchanged with the targeted application port. By using the `iptables` command-line tool, the proxy internally redirects the incoming traffic to the web applications to a port of a python socket. At this socket, it then invokes the proxy function specified by `proxy.py` with all incoming and outgoing traffic.

The proxy function specified by `proxy.py` the actual translation of the headers take place. In case of incoming traffic, it stores information like the referer header, which we, later on, need for the translation of frame-ancestors into x-frame-options. In case of outgoing traffic (so the response from the Web application), we check if the response is HTML and if so, we parse the HTTP header of the response. If only one of the two headers is present, we use our retrofit_headers function to translate them into one another. The process of this transformation is explained in detail in the retrofitting security section of our paper.

The third script that is used is `utils.py`. It includes functions for parsing HTTP header out of the raw traffic string, parsing the CSP header into its directives and source expressions, as well as other utilities that are used throughout the retrofitting step.

To test the implementation of the proxy, we also created a small test server. The page delivered by this server can handle two different HTTP GET parameters: First `xfo`, which is reflected as X-Frame-Options header value, and secondly`csp`, which is reflected as the value of CSP's frame-ancestors directive.


### Requirements:

The proxy itself requires **python3** as well as the **python3-tldextract** library to be installed on the server. In addition to that, the system must support the **iptables** command-line tool to be installed. Thus it is (currently) only executable on Linux systems. The proxy is started with `python3 proxy.py <ip_version> <web_application_port>`, where `ip_version` is the version of the IP (4 or 6), and `web_application_port` is the port that is used for the incoming traffic of the Web application.

If you want to use our test Web server (`http_test.py`) to test the proxy, you need to have **python2** installed. The server can be started with `python2 http_test.py`, which results in hosting a SimpleHTTPServer on port 8080.
