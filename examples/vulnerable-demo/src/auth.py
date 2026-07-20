import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec

def legacy_hash(pw):
    return hashlib.md5(pw.encode()).hexdigest()

def fingerprint(data):
    return hashlib.sha1(data).hexdigest()

def gen_keys():
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP256R1())
    return rsa_key, ec_key

def good_hash(data):
    return hashlib.sha256(data).hexdigest()
