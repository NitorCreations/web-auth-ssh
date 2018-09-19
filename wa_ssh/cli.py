from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
from builtins import str
import argparse
import os
import re
import sys
import _thread
import http.server
import http.server
import socketserver
import webbrowser
import time
import urllib.request, urllib.parse, urllib.error
from wa_ssh import load_config
from requests import get
from wa_ssh.utils import get_query_param, get_open_port, stdchannel_redirected

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
    print(resp.content)

def wa_privkey():
    parser = argparse.ArgumentParser(description="Fetch private key")
    parser.add_argument("user_at_host", help="The host that requests keys for login")
    parser.add_argument("-c", "--config", help="Configuration file", nargs="*")
    args = parser.parse_args()
    user, host, keyserver = map_user_at_host(args.config, args.user_at_host)
    key = get_privkey(args.config, host, user, keyserver)
    if key:
        print(key)
    else:
        print("No response")
        sys.exit(1)

def wa_user_host():
    parser = argparse.ArgumentParser(description="Get mapping for user and host from wa-ssh configuration files")
    parser.add_argument("user_at_host", help="A pointer to a configuration or a direct reference in the form user@hostname")
    parser.add_argument("-c", "--config", help="Configuration file", nargs="*")
    args = parser.parse_args()
    mapped_user, mapped_host, _ = map_user_at_host(args.config, args.user_at_host)
    print(mapped_user + " " + mapped_host)

def map_user_at_host(extra_confs, user_at_host):
    pattern = re.compile("([^@]*)@(.*)")
    match = pattern.match(user_at_host)
    if match:
        user = match.group(1)
        host = match.group(2)
    else:
        user = None
        host = user_at_host
    return map_user_host(extra_confs, user, host)

def map_user_host(extra_confs, user, host):
    conf = load_config(extra_confs=extra_confs)
    mapped_host = None
    mapped_user = None
    keyserver = conf["keyserver"]
    if "hosts" in conf:
        for conf_host, host_conf in conf["hosts"]:
            matches = False
            try:
                matches = re.compile(conf_host).match(host) is not None
            except:
                pass
            if conf_host == host or matches:
                if "HostName" in host_conf:
                    mapped_host = host_conf['HostName']
                if not user and "User" in host_conf:
                    mapped_user = host_conf["User"]
                if "KeyServer" in host_conf:
                    keyserver = host_conf["KeyServer"]
    if not mapped_user:
        mapped_user = user
    if not mapped_host:
        mapped_host = host
    return mapped_user, mapped_host, keyserver

def get_privkey(extra_confs, host, username, keyserver):
    global SERVER
    port = get_open_port()
    Handler = KeyResponseHandler
    SERVER = socketserver.TCPServer(("127.0.0.1", port), Handler)
    url = keyserver + "/privkey/" + host + "/" + username + "?port=" + str(port)
    with stdchannel_redirected(sys.stdout, os.devnull):
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

class KeyResponseHandler(http.server.BaseHTTPRequestHandler):
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
            _thread.start_new_thread(stop_server, (SERVER,))

    def do_HEAD(self):
        """Serve a HEAD request."""
        self.send_head()

    def send_head(self):
        key = get_query_param(self.path, "key")
        self._set_headers()
        if key:
            global KEY_RESPONSE
            KEY_RESPONSE = urllib.parse.unquote(key).replace("+RSA+PRIVATE+KEY", " RSA PRIVATE KEY")
            return privkey_response
        else:
            return None

    def log_message(self, format, *args):
        return
