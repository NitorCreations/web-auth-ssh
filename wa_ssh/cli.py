import argparse
import sys
import thread
import SimpleHTTPServer
import BaseHTTPServer
import SocketServer
import webbrowser
import time
import urllib
from wa_ssh import load_config
from requests import get
from wa_ssh.utils import get_query_param, get_open_port

KEY_RESPONSE = None
SERVER = None

def wa_pubkeys():
    parser = argparse.ArgumentParser(description="Fetch public keys")
    parser.add_argument("host", help="The host that requests keys for login")
    parser.add_argument("username", help="The user that requests keys for login")
    parser.add_argument("-c", "--config", help="Configuration file", nargs="*")
    args = parser.parse_args()
    conf = load_config(extra_confs=args.config)
    url = conf['keyserver'] + "/pubkey/" + args.host + "/" + args.username
    resp = get(url)
    print resp.content

def wa_privkey():
    parser = argparse.ArgumentParser(description="Fetch private key")
    parser.add_argument("host", help="The host that requests keys for login")
    parser.add_argument("username", help="The user that requests keys for login")
    parser.add_argument("-c", "--config", help="Configuration file", nargs="*")
    args = parser.parse_args()
    key = get_privkey(args.config, args.host, args.username)
    if key:
        print key
    else:
        print "No response"
        sys.exit(1)

def wa_ssh():
    parser = argparse.ArgumentParser(description="Login with an ssh key gotten through a web login")
    parser.add_argument("-i", "--identity", help="Additional ssh identities to add to ssh agent of the session", nargs="*")

def get_privkey(extra_confs, host, username):
    global SERVER
    conf = load_config(extra_confs=extra_confs)
    port = get_open_port()
    Handler = KeyResponseHandler
    SERVER = SocketServer.TCPServer(("127.0.0.1", port), Handler)
    url = conf['keyserver'] + "/privkey/" + host + "/" + username + "?port=" + str(port)
    webbrowser.open(url, new=2, autoraise=False)
    try:
        SERVER.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        SERVER.shutdown()
    if KEY_RESPONSE:
        return KEY_RESPONSE
    else:
        return None

privkey_response = """
<html>
  <head><title>Key received</title></head>
  <body>
  <p>Key received, you may close this window.</p>
  <script>
    window.close();
  </script>
  </body>
</html>"""

class KeyResponseHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            try:
                self.wfile.write(f)
            finally:
                self.wfile.flush()
                self.wfile.close()
            global SERVER
            def stop_server(server):
                server.shutdown()
            thread.start_new_thread(stop_server, (SERVER,))

    def do_HEAD(self):
        """Serve a HEAD request."""
        self.send_head()

    def send_head(self):
        key = get_query_param(self.path, "key")
        self._set_headers()
        if key:
            global KEY_RESPONSE
            KEY_RESPONSE = urllib.unquote(key)
            return privkey_response
        else:
            return None

