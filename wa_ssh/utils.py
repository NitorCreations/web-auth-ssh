from urlparse import urlparse
import socket

def get_query_param(path, paramName):
    url = urlparse(path)
    for param in url.query.split("&"):
        if param.startswith(paramName + "="):
            return param.split("=", 1)[1]
    return None

def get_open_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("",0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port
