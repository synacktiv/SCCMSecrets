from enum import Enum

DP_DOWNLOAD_HEADERS = {
    "User-Agent": "SMS CCM 5.0 TS"
}
MP_INTERACTIONS_HEADERS = {
    "User-Agent": "ConfigMgr Messaging HTTP Sender"
}

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

BRUTEFORCE_THREADS = 5
DOWNLOAD_THREADS = 2

OID_MAPPING = {
    '1.2.840.113549.3.7': "des-ede3-cbc",

    # PKCS1 v2.2
    '1.2.840.113549.1.1.1': 'rsaEncryption',
    '1.2.840.113549.1.1.2': 'md2WithRSAEncryption',
    '1.2.840.113549.1.1.3': 'md4withRSAEncryption',
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1-with-rsa-signature',
    '1.2.840.113549.1.1.6': 'rsaOAEPEncryptionSET',
    '1.2.840.113549.1.1.7': 'id-RSAES-OAEP',
    '1.2.840.113549.1.1.8': 'id-mgf1',
    '1.2.840.113549.1.1.9': 'id-pSpecified',
    '1.2.840.113549.1.1.10': 'rsassa-pss',

    # AES
    '2.16.840.1.101.3.4.1.41': 'aes256_ecb',
    '2.16.840.1.101.3.4.1.42': 'aes256_cbc',
    '2.16.840.1.101.3.4.1.43': 'aes256_ofb',
    '2.16.840.1.101.3.4.1.44': 'aes256_cfb',
    '2.16.840.1.101.3.4.1.45': 'aes256_wrap',
    '2.16.840.1.101.3.4.1.46': 'aes256_gcm',
    '2.16.840.1.101.3.4.1.47': 'aes256_ccm',
    '2.16.840.1.101.3.4.1.48': 'aes256_wrap_pad'
}

class ANONYMOUSDP(Enum):
    ENABLED = 0
    DISABLED = 1
    UNKNOWN = 2

class SCENARIOS(Enum):
    NoCredsNoAnonymous = 0
    NoCredsAnonymous = 1
    UserCreds = 2
    MachineCreds = 3
