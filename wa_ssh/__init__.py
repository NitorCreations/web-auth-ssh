from os.path import expanduser, exists, isfile, sep
from collections import OrderedDict
import yaml

HOME = expanduser("~")

CONFS = [ "/etc/web-auth-ssh.conf", "C:\\Windows\\web-auth-ssh.conf", HOME + sep + ".web-auth-ssh"]

def yaml_load(stream):
    class OrderedLoader(yaml.SafeLoader):
        pass

    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return OrderedDict(loader.construct_pairs(node))
    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping)

    return yaml.load(stream, OrderedLoader)

def load_config(extra_confs=[]):
    configs = OrderedDict([
        ("keyserver_port", "8017"),
        ("privkey_timeout", 120),
        ("userheader", "x-auth-name"),
        ("groupsheader", "x-auth-groups"),
        ("default_expiry_hours", 12)
    ])
    if extra_confs is None:
        extra_confs = []
    check_confs = CONFS + extra_confs
    for conf in check_confs:
        if exists(conf) and isfile(conf):
            with open(conf) as conf_file:
                try:
                    configs.update(yaml_load(conf_file))
                except IOError:
                    pass
    return configs