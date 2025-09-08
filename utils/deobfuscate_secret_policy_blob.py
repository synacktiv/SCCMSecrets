# Taken from sccmwtf https://github.com/xpn/sccmwtf
# Credits @xpn
# Adaptation to support AES256 deobfuscation taken from @1058274 in their impacket PR (https://github.com/fortra/impacket/pull/2020)
import logging

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, ciphers
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

logger = logging.getLogger(__name__)

def mscrypt_derive_key_sha1(secret:bytes):
    buf1 = bytearray([0x36] * 64)
    buf2 = bytearray([0x5C] * 64)

    digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest.update(secret)
    hash_ = digest.finalize()

    for i in range(len(hash_)):
        buf1[i] ^= hash_[i]
        buf2[i] ^= hash_[i]

    digest1 = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest1.update(buf1)
    hash1 = digest1.finalize()

    digest2 = hashes.Hash(hashes.SHA1(), backend=default_backend())
    digest2.update(buf2)
    hash2 = digest2.finalize()

    derived_key = hash1 + hash2
    return derived_key

def deobfuscate_secret_policy_blob(output):
    if isinstance(output, str):
        output = bytes.fromhex(output)
    
    data_length = int.from_bytes(output[52:56], 'little')
    buffer = output[64:64+data_length]

    key = mscrypt_derive_key_sha1(output[4:4+0x28])
    blob_prefix = output[:2]
    if blob_prefix == b'\x89\x13':
        logger.info("[INFO] Policy obfuscated with triple DES")
        block_cipher_algorithm = algorithms.TripleDES(key[:24])
    elif blob_prefix == b'\x8a\x13':
        logger.info("[INFO] Policy obfuscated with AES256")
        block_cipher_algorithm = algorithms.AES256(key[:32])
    else:
        raise Exception("Unexpected starting bytes for obfuscated blob")

    iv = bytes([0] * (block_cipher_algorithm.block_size // 8))
    cipher = Cipher(block_cipher_algorithm, modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(buffer) + decryptor.finalize()

    padder = padding.PKCS7(block_cipher_algorithm.block_size).unpadder()
    decrypted_data = padder.update(decrypted_data) + padder.finalize()

    try:
        decrypted_data = decrypted_data.decode('utf-16-le')
    except:
        decrypted_data = decrypted_data.hex()
    return decrypted_data
