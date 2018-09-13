from keygen import keygen, get_key
from os.path import expanduser, exists, isfile 
import yaml

HOME = expanduser("~")

CONFS = [ "/etc/web-auth-ssh.conf", "C:\\Windows\\web-auth-ssh.conf", HOME + "/.web-auth-ssh"]

def load_config():
    configs = {
        "keydir": "/tmp/keyserver"
    }
    for conf in CONFS:
        if exists(conf) and isfile(conf):
            with open(conf) as conf_file:
                try:
                    configs.update(yaml.load(conf_file))
                except IOError:
                    pass
    return configs