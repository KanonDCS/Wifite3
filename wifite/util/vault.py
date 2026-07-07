import os
import json
import struct
import hashlib
import secrets
import getpass

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    _CRYPTO_AVAILABLE = True
except ImportError:
    _CRYPTO_AVAILABLE = False

_SALT_LEN    = 32
_NONCE_LEN   = 12
_ITER_COUNT  = 390000
_KEY_LEN     = 32
_VERSION     = b'\x03'


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_ITER_COUNT,
    )
    return kdf.derive(password.encode('utf-8'))


def is_available():
    return _CRYPTO_AVAILABLE


def encrypt(plaintext_dict: list, password: str) -> bytes:
    salt  = secrets.token_bytes(_SALT_LEN)
    nonce = secrets.token_bytes(_NONCE_LEN)
    key   = _derive_key(password, salt)
    data  = json.dumps(plaintext_dict, indent=2).encode('utf-8')
    ct    = AESGCM(key).encrypt(nonce, data, None)
    return _VERSION + salt + nonce + ct


def decrypt(blob: bytes, password: str) -> list:
    if blob[0:1] != _VERSION:
        raise ValueError('Unknown vault version')
    salt  = blob[1:1 + _SALT_LEN]
    nonce = blob[1 + _SALT_LEN:1 + _SALT_LEN + _NONCE_LEN]
    ct    = blob[1 + _SALT_LEN + _NONCE_LEN:]
    key   = _derive_key(password, salt)
    data  = AESGCM(key).decrypt(nonce, ct, None)
    return json.loads(data.decode('utf-8'))


def save(vault_path: str, records: list, password: str):
    blob = encrypt(records, password)
    tmp  = vault_path + '.tmp'
    old_mask = os.umask(0o177)
    try:
        with open(tmp, 'wb') as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, vault_path)
    finally:
        os.umask(old_mask)


def load(vault_path: str, password: str) -> list:
    with open(vault_path, 'rb') as f:
        blob = f.read()
    return decrypt(blob, password)


def prompt_password(confirm=False) -> str:
    pw = getpass.getpass('Vault password: ')
    if confirm:
        pw2 = getpass.getpass('Confirm vault password: ')
        if pw != pw2:
            raise ValueError('Passwords do not match')
    return pw
