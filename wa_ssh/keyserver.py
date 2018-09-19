from __future__ import print_function
from future import standard_library
standard_library.install_aliases()
import argparse
import os
import http.server
import http.server
import socketserver
import socket
import urllib.request, urllib.parse, urllib.error
import re
from collections import OrderedDict
from wa_ssh import load_config
from wa_ssh.keygen import get_key
from wa_ssh.utils import get_query_param
from urllib.parse import urlparse

CONF = load_config()

def start(extra_confs=[]):
    global CONF
    CONF = load_config(extra_confs=extra_confs)
    port = int(CONF['keyserver_port'])
    Handler = KeyRequestHandler
    httpd = socketserver.TCPServer(("127.0.0.1", port), Handler)
    print("serving at port", port)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()

class KeyRequestHandler(http.server.BaseHTTPRequestHandler):
    def _set_headers(self, status=200, location=None):
        self.send_response(status)
        self.send_header('Content-type', 'text/plain')
        if location:
            self.send_header('Location', location)
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

    def do_HEAD(self):
        """Serve a HEAD request."""
        self.send_head()

    def send_head(self):
        path = translate_path(self.path)
        if path[0] == "privkey":
            redirect_port = get_redirect_port(self.path)
            req_user = None
            req_groups = []
            if CONF['userheader'] in self.headers:
                req_user = self.headers[CONF['userheader']]
            if CONF['groupsheader'] in self.headers:
                req_groups = self.headers[CONF['groupsheader']].split(",")
            grant, parameters = grant_access(path[1], path[2], req_user, req_groups)
            if not grant:
                self._set_headers(status=403)
                return None
            expiry_hours = shortest_expiry(parameters)
            priv, pub = get_key(path[1], path[2], expiry_hours)
            location = "http://localhost:" + redirect_port + "/?" + urllib.parse.urlencode({"key": priv})
            self._set_headers(status=302, location=location)
            return None
        elif path[0] == "pubkey":
            self._set_headers()
            priv, pub = get_key(path[1], path[2], 0)
            return pub

def translate_path(path):
    url = urlparse(path)
    return urllib.parse.unquote(url.path.rstrip()).split("/")[1:]

def get_redirect_port(path):
    port = get_query_param(path, "port")
    if port:
        return port
    else:
        return "0"

def grant_access(host, username, req_user, req_groups):
    if 'access' not in CONF:
        return False, None
    grant = False
    parameters = []
    for policy in CONF['access']:
        if 'criteria' not in policy or 'permissions' not in policy:
            return False, None
        if criteria_matches(policy['criteria'], host, username, req_user, req_groups):
            if "deny" in policy['permissions']:
                return False, None
            if req_user is None and "noauth" in policy['permissions']:
                grant = True
            if not req_groups and "noauth" in policy['permissions']:
                grant = True
            if req_user == username and "login" in policy['permissions']:
                grant = True
            if req_user != username and "changeuser" in policy['permissions']:
                grant = True
            if 'parameters' in policy:
                parameters.append(policy['parameters'])
    return grant, parameters


def criteria_matches(criteria, host, username, req_user, req_groups):
    for next_criteria in criteria:
        if "host" in next_criteria:
            if not entry_matches(next_criteria['host'], host):
                return False
        if "user" in next_criteria:
            if not entry_matches(next_criteria["user"], req_user):
                return False
        if "targetuser" in next_criteria:
            if not entry_matches(next_criteria["targetuser"], username):
                return False
        if "group" in next_criteria:
            match_found = False
            for group in req_groups:
                if entry_matches(next_criteria["group"], group):
                    match_found = True
            if not match_found:
                return False
    return True

def entry_matches(criteria_entry, entry):
    if isinstance(criteria_entry, OrderedDict) and 're' in criteria_entry:
        host_re = re.compile(criteria_entry['re'])
        return host_re.match(entry) is not None
    else:
        return criteria_entry == entry

def shortest_expiry(parameters):
    expiry = None
    for next_params in parameters:
        if "expiry_hours" in next_params:
            if not expiry or (expiry and parameters['expiry_hours'] < expiry):
                expiry = parameters['expiry_hours']
    if not expiry:
        return CONF["default_expiry_hours"]
    else:
        return expiry

def main():
    parser = argparse.ArgumentParser(description="Start keyserver")
    parser.add_argument("-c", "--config", help="Configuration file", nargs="*")
    args = parser.parse_args()
    start(extra_confs=args.config)
