import argparse
from wa_ssh import load_config
from requests import get

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
