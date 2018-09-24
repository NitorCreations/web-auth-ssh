import json
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from n_vault import Vault

VAULT = Vault()
def _keygen():
    key = RSA.generate(4096)
    return key.exportKey(format="PEM"), key.publickey().exportKey(format="OpenSSH")

def get_key(host, username, expiry_hours):
    userinfo ={"privateKey": "", "publicKey": ""}
    try:
        userinfo = json.loads(VAULT.lookup(host + "/" + username))
        expires = date_from_str(userinfo['expires'])
        if expires < datetime.now() and expiry_hours > 0:
            update_userinfo(userinfo, host, username, expiry_hours)
    except:
        if expiry_hours == 0:
            return None, None
        userinfo = {}
        update_userinfo(userinfo, host, username, expiry_hours)
    return userinfo['privateKey'], userinfo['publicKey']

def date_from_str(datestr):
    return datetime.strptime(datestr, "%Y-%m-%dT%H:%M:%S.%fZ")

def date_to_str(timestamp):
    return timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def get_expiry_hours(username, expiry_hours):
    try:
        return int(VAULT.lookup(username + '.expiry'))
    except:
        return expiry_hours

def update_userinfo(userinfo, host, username, expiry_hours):
    userinfo['privateKey'], userinfo['publicKey'] = _keygen()
    userinfo['expires'] = date_to_str(datetime.now() + timedelta(get_expiry_hours(username, expiry_hours)))
    VAULT.store(host + "/" + username, json.dumps(userinfo))
