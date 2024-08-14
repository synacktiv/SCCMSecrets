from cryptography                                       import x509
from cryptography.x509.oid                              import NameOID
from cryptography.x509                                  import ObjectIdentifier
from cryptography.hazmat.primitives                     import serialization, hashes
from cryptography.hazmat.primitives.asymmetric          import rsa
from cryptography.hazmat.primitives.asymmetric.padding  import PKCS1v15
from datetime                                           import datetime, timedelta

def createCertificate(privatekey):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "ConfigMgr Client"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        privatekey.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow() - timedelta(days=2)
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.KeyUsage(digital_signature=True, key_encipherment=False, key_cert_sign=False,
                                key_agreement=False, content_commitment=False, data_encipherment=True,
                                crl_sign=False, encipher_only=False, decipher_only=False),
        critical=False,
    ).add_extension(
        x509.ExtendedKeyUsage([ObjectIdentifier("1.3.6.1.4.1.311.101.2"), ObjectIdentifier("1.3.6.1.4.1.311.101")]),
        critical=False,
    ).sign(privatekey, hashes.SHA256())

    return cert

def createPrivateKey():
    privatekey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return privatekey

def SCCMSign(private_key, data):
        signature = private_key.sign(data, PKCS1v15(), hashes.SHA256())
        signature_rev = bytearray(signature)
        signature_rev.reverse()
        return bytes(signature_rev)
    
def buildMSPublicKeyBlob(private_key):
    blobHeader = b"\x06\x02\x00\x00\x00\xA4\x00\x00\x52\x53\x41\x31\x00\x08\x00\x00\x01\x00\x01\x00"
    blob = blobHeader + private_key.public_key().public_numbers().n.to_bytes(int(private_key.key_size / 8), byteorder="little")
    return blob.hex().upper()