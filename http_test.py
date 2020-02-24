from urlparse import parse_qsl, urlsplit
import SimpleHTTPServer
import SocketServer

HTML = """
<!DOCTYPE html>
<html>
 <head>
  <meta charset="utf-8">
  <title>Framing Test</title>
  <meta name="author" content="">
  <meta name="description" content="">
  <meta name="viewport" content="width=device-width, initial-scale=1">
 </head>
 <body>
  <h1>XFO: %s</h1>
  <h1>CSP: %s</h1>
 </body>
</html>
"""


def process_get_request(self):
    """
    Takes CSP / XFO from the GET parameters and reflects those.
    """
    query_components = dict(parse_qsl(urlsplit(self.path).query))
    self.send_response(200)
    self.send_header('Content-Type', 'text/html')
    xfo, csp = ('', '')
    if 'xfo' in query_components:
        xfo = query_components["xfo"]
        self.send_header('X-Frame-Options', xfo)
    if 'csp' in query_components:
        csp = query_components["csp"]
        self.send_header('Content-Security-Policy', csp)
    self.end_headers()
    self.wfile.write(HTML % (xfo.replace('<', ''), csp.replace('<', '')))


Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
Handler.do_GET = process_get_request
httpd = SocketServer.TCPServer(("", 8080), Handler)
httpd.serve_forever()
