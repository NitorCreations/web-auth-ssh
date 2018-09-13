import json
from datetime import datetime, timedelta
import pytz
from Crypto.PublicKey import RSA
from n_vault import Vault

VAULT = Vault()
def keygen():
    key = RSA.generate(4096)
    return key.exportKey(format="PEM"), key.publickey().exportKey(format="OpenSSH")

def get_key(username):
    userinfo ={"privateKey": "", "publicKey": ""}
    try:
        userinfo = json.loads(VAULT.lookup(username))
        expires = date_from_str(userinfo['expires'])
        if expires < datetime.now():
            update_userinfo(userinfo, username)
    except:
        userinfo = {}
        update_userinfo(userinfo, username)
    return userinfo['privateKey'], userinfo['publicKey']

def date_from_str(datestr):
    return datetime.strptime(datestr, "%Y-%m-%dT%H:%M:%S.%fZ")

def date_to_str(timestamp):
    return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def get_expiry_hours(username):
    try:
        return int(VAULT.lookup(username + '.expiry'))
    except:
        return 24

def update_userinfo(userinfo, username):
    userinfo['privateKey'], userinfo['publicKey'] = keygen()
    userinfo['expires'] = date_to_str(datetime.now() + timedelta(get_expiry_hours(username)))
    VAULT.store(username, json.dumps(userinfo))
