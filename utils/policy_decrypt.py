import logging

from cryptography.hazmat.primitives.asymmetric      import padding
from cryptography.hazmat.primitives.hashes          import SHA1
from cryptography.hazmat.primitives.ciphers         import Cipher, algorithms, modes
from cryptography.hazmat.backends                   import default_backend
from pyasn1.codec.der.decoder                       import decode
from pyasn1_modules                                 import rfc5652

from conf                                           import bcolors, OID_MAPPING

logger = logging.getLogger(__name__)


def decrypt_key_OAEP(encrypted_key, private_key):
    return private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=SHA1()), algorithm=SHA1(), label=None))

def decrypt_key_RSA(encrypted_key, private_key):
    return private_key.decrypt(encrypted_key, padding.PKCS1v15())

def decrypt_body_triple_DES(body, plaintextkey, iv):
    cipher = Cipher(algorithms.TripleDES(plaintextkey), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(body) + decryptor.finalize()
    return plaintext.decode('utf-16le')

def decrypt_body_AES_CBC(body, plaintextkey, iv):
    cipher = Cipher(algorithms.AES(plaintextkey), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(body) + decryptor.finalize()
    return plaintext.decode('utf-16le')

def decrypt_secret_policy(policy_response, private_key):
    content, rest = decode(policy_response, asn1Spec=rfc5652.ContentInfo())
    content, rest = decode(content.getComponentByName('content'), asn1Spec=rfc5652.EnvelopedData())
    encryptedRSAKey = content['recipientInfos'][0]['ktri']['encryptedKey'].asOctets()
    keyEncryptionOID = str(content['recipientInfos'][0]['ktri']['keyEncryptionAlgorithm']['algorithm'])
    iv = content['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters'].asOctets()[2:]
    body = content['encryptedContentInfo']['encryptedContent'].asOctets()
    bodyEncryptionOID = str(content['encryptedContentInfo']['contentEncryptionAlgorithm']['algorithm'])

    try:
        if OID_MAPPING[keyEncryptionOID] == 'rsaEncryption':
            plaintextkey = decrypt_key_RSA(encryptedRSAKey, private_key)
        elif OID_MAPPING[keyEncryptionOID] == 'id-RSAES-OAEP':
            plaintextkey = decrypt_key_OAEP(encryptedRSAKey, private_key)
        else:
            logger.error(f"{bcolors.FAIL}[-] Key decryption algorithm {OID_MAPPING[keyEncryptionOID]} is not currently implemented.{bcolors.ENDC}")
            return
    except KeyError as e:
        logger.error(f"{bcolors.FAIL}[-] Unknown key decryption algorithm.{bcolors.ENDC}")
        return

    try:
        if OID_MAPPING[bodyEncryptionOID] == 'des-ede3-cbc':
            plaintextbody = decrypt_body_triple_DES(body, plaintextkey, iv)
        elif OID_MAPPING[bodyEncryptionOID] == 'aes256_cbc':
            plaintextbody = decrypt_body_AES_CBC(body, plaintextkey, iv)
        else:
            logger.error(f"{bcolors.FAIL}[-] Body decryption algorithm {OID_MAPPING[bodyEncryptionOID]} is not currently implemented.{bcolors.ENDC}")
            return
    except KeyError as e:
        logger.error(f"{bcolors.FAIL}[-] Unknown body decryption algorithm.{bcolors.ENDC}")
        return

    return plaintextbody