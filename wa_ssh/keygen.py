import json
import uuid
from cryptography.x509.extensions import _key_identifier_from_public_key
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtensionOID, ExtendedKeyUsageOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from n_vault import Vault

VAULT = None
ONE_DAY = timedelta(1, 0, 0)
ISSUER = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"Web Auth CA")])

def _vault():
    if not VAULT:
        VAULT = Vault()
    return VAULT

def _key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend())

def _keygen():
    private_key = _key()
    private_str = private_key_to_bytes(private_key).decode()
    public_str = public_key_to_bytes(private_key.public_key()).decode()
    return private_str, public_str

def get_key(host, username, expiry_hours):
    userinfo ={"privateKey": "", "publicKey": ""}
    try:
        userinfo = json.loads(_vault().lookup(host + "/" + username))
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
        return int(_vault().lookup(username + '.expiry'))
    except:
        return expiry_hours

def cert_to_bytes(certificate):
    return certificate.public_bytes(encoding=serialization.Encoding.PEM,)

def private_key_to_bytes(key):
    return key.private_bytes(encoding=serialization.Encoding.PEM,
                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                             encryption_algorithm=serialization.NoEncryption())

def public_key_to_bytes(key):
    return key.public_bytes(encoding=serialization.Encoding.OpenSSH,
                            format=serialization.PublicFormat.OpenSSH)

def update_userinfo(userinfo, host, username, expiry_hours):
    userinfo['privateKey'], userinfo['publicKey'] = _keygen()
    userinfo['expires'] = date_to_str(datetime.now() + timedelta(get_expiry_hours(username, expiry_hours)))
    _vault().store(host + "/" + username, json.dumps(userinfo))

def generate_ca(country, state, locality, common_name, org_name, org_unit, valid_days):
    ca_key = _key()
    ca_public_key = ca_key.public_key()
    validity_end = datetime.today() + timedelta(days=valid_days)
    validity_start = datetime.today() - ONE_DAY
    serial_number = x509.random_serial_number()
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit)
    ])

    ca_builder = x509.CertificateBuilder()
    ca_builder = ca_builder.serial_number(serial_number)
    ca_builder = ca_builder.subject_name(ca_subject)
    ca_builder = ca_builder.issuer_name(ISSUER)
    ca_builder = ca_builder.not_valid_before(validity_start)
    ca_builder = ca_builder.not_valid_after(validity_end)
    ca_builder = ca_builder.public_key(ca_public_key)
    ca_builder = ca_builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    ca_builder = ca_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ca_public_key), critical=False,
    )
    ca_builder = ca_builder.add_extension(
        x509.AuthorityKeyIdentifier(_key_identifier_from_public_key(ca_public_key), [x509.DirectoryName(ISSUER)], serial_number), critical=False,
    )

    certificate = ca_builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return ca_key, certificate


def create_vpn_certs(country, state, locality, common_name, org_name, org_unit, user_name, user_given_name,
                     user_surname, user_email, valid_days):

    ca_key, ca_certificate = generate_ca(country, state, locality, common_name, org_name, org_unit, valid_days)
    ca_public_key = ca_key.public_key()
    client_key = _key()
    client_public_key = client_key.public_key()


    client_subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.COMMON_NAME, user_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org_name),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, org_unit),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, user_email),
        x509.NameAttribute(NameOID.GIVEN_NAME, user_given_name),
        x509.NameAttribute(NameOID.SURNAME, user_surname),
    ])
    validity_end = datetime.today() + timedelta(days=valid_days)
    validity_start = datetime.today() - ONE_DAY
    serial_number = x509.random_serial_number()

    crt_builder = x509.CertificateBuilder()
    crt_builder = crt_builder.serial_number(serial_number)
    crt_builder = crt_builder.subject_name(client_subject)
    crt_builder = crt_builder.issuer_name(ISSUER)
    crt_builder = crt_builder.not_valid_before(validity_start)
    crt_builder = crt_builder.not_valid_after(validity_end)
    crt_builder = crt_builder.public_key(client_public_key)
    crt_builder = crt_builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )
    crt_builder = crt_builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(client_public_key), critical=False,
    )
    crt_builder = crt_builder.add_extension(
        x509.AuthorityKeyIdentifier(_key_identifier_from_public_key(ca_public_key), [x509.DirectoryName(ISSUER)], ca_certificate.serial_number), critical=False,
    )

    client_certificate = crt_builder.sign(
        private_key=ca_key, algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return ca_key, ca_certificate, client_key, client_certificate

