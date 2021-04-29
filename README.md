
# SSH Trusted Authority

A secure SSH public keys directory.

This is the open source script that processes the source data to build a trusted SSH servers public keys directory. The SSH public keys can then be downloaded as HTTPS files, and the connections with the SSH servers are trusted from the first time.

More info on https://sshta.conserity.org


## Requirements

* Python 3 (tested on 3.6 and 3.8)
* cryptography >= 2.1.4
* ecdsa >= 0.13

`python3 -m pip install cryptography ecdsa`

## Use

Write a JSON file with the servers info :

```
  "server.domain": {
    "info-url": "https:URLWHEREPUBLISHEDKEYS",
    "info-provided": "fingerprint" OR "SSHPubKey",
    "keys": [
      {
        "type": "rsa" OR "ecdsa" OR "ed25519",
        "params": BitLength for RSA OR curve code for ECDSA,
        "data": "TheDATAprovidedSSHpublickeyORfingerprint"
      },
      ...
    ]
  },
  ...
```

Then run the process_source script : `python3 process_source.py`

That will :

* load the source data
* decode and check data integrity
* read the current key at the remote server online
* match the current key seen with the data provided (fingerprint or key)
* build a list of all the keys data and save it
* build a known_hosts file with all the public keys

The input and outputs are maintained on https://sshta.conserity.org
