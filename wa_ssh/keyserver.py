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
    host = "127.0.0.1"
    if "keyserver_host" in CONF:
        host = CONF["keyserver_host"]
    Handler = KeyRequestHandler
    httpd = socketserver.TCPServer((host, port), Handler)
    print("Serving at {0}:{1}".format(host, port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.shutdown()

class KeyRequestHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        """Serve a GET request."""
        f = self.send_head()
        if f:
            try:
                self.wfile.write(f.encode())
            finally:
                self.wfile.flush()

    def do_HEAD(self):
        """Serve a HEAD request."""
        self.send_head()

    def send_head(self):
        response = get_response(self.path, self.headers)
        self.send_response(response["statusCode"])
        for name, key in response["headers"].items():
            self.send_header(name, key)
        self.end_headers()
        if "body" in response and response["body"]:
            return response["body"]

def lambda_handler(event, context):
    return get_response(event["path"], event["headers"])


def get_response(path, headers):
    ret_headers = OrderedDict()
    ret = OrderedDict([("statusCode", 200),
                       ("headers", ret_headers),
                       ("isBase64Encoded", False),
                       ("body", None)])
    path = translate_path(path)
    if path[0] == "privkey":
        redirect_port = get_redirect_port(path)
        req_user, req_groups = get_user_and_groups(headers)
        grant, parameters = grant_access(path[1], path[2], req_user, req_groups)
        if not grant:
            set_headers(ret, status=403)
            return ret
        expiry_hours = shortest_expiry(parameters)
        priv, pub = get_key(path[1], path[2], expiry_hours)
        location = "http://localhost:" + redirect_port + "/?" + urllib.parse.urlencode({"key": priv})
        set_headers(ret, status=302, location=location)
        return ret
    elif path[0] == "pem":
        req_user, req_groups = get_user_and_groups(headers)
        grant, parameters = grant_access(path[1], path[2], req_user, req_groups)
        if not grant:
            set_headers(ret, status=403)
            return ret
        expiry_hours = shortest_expiry(parameters)
        priv, pub = get_key(path[1], path[2], expiry_hours)
        set_headers(ret, content_type="application/x-pem-file")
        ret["body"] = priv
    elif path[0] == "pubkey":
        set_headers(ret, file_name="authorized_keys")
        priv, ret["body"] = get_key(path[1], path[2], 0)
        return ret

def get_user_and_groups(headers):
    req_user = None
    req_groups = []
    if CONF['userheader'] in headers:
        req_user = headers[CONF['userheader']]
    if CONF['groupsheader'] in headers:
        req_groups = headers[CONF['groupsheader']].split(",")
    return req_user, req_groups

def set_headers(response, status=200, location=None, content_type="text/plain", file_name=None):
    response["statusCode"] = status
    response["headers"]["content-type"] = content_type
    if location:
        response["headers"]["location"] = location
    if file_name:
        response["headers"]["content-disposition"] = "attachment; filename=" + file_name

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
