import os
import SimpleHTTPServer
import BaseHTTPServer
import SocketServer
import socket
import urlparse
import urllib
from . import load_config

conf = load_config()

def start():
    port = get_open_port()
    Handler = KeyRequestHandler
    httpd = SocketServer.TCPServer(("", port), Handler)
    print "serving at port", port
    httpd.serve_forever()

def get_open_port():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("",0))
        s.listen(1)
        port = s.getsockname()[1]
        s.close()
        return port

class KeyRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            self.wfile.write(f)

    def do_HEAD(self):
        """Serve a HEAD request."""
        self.send_head()

    def send_head(self):
        path = self.translate_path(self.path)
        if path[0] == "privkey":
            return None
        elif path[0] == "pubkey":
            return get_pubkeys(path[1], path[2])

    def translate_path(self, path):
        path = path.split('?',1)[0]
        path = path.split('#',1)[0]
        return urllib.unquote(path.rstrip()).split("/")

def get_pubkeys(server, user):
        return None