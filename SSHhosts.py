# Keys processing and checking library for SSH Trusted Authority
# Copyright (C) 2021 BitLogiK - Antoine FERRON

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


import subprocess
from sshpubkeys import SSHKey


class HostKey(SSHKey):
    def __init__(self, key_infos):
        keytype = key_infos["type"]
        self.params = key_infos["params"]
        if keytype == "ecdsa":
            self.keytype_id = f"ecdsa-sha2-{self.params}"
        else:
            self.keytype_id = f"ssh-{keytype}"
        super().__init__(f"{self.keytype_id} {key_infos['pubkey']}", strict=True)
        self.parse()
        self.pkdata = key_infos["pubkey"]

    def get_sshformat_data(self):
        return self.pkdata

    def get_key_values(self, keytype):
        # Values in hex string
        if keytype == "ecdsa":
            # (x,y) of the EC curve point
            pub_point = self.ecdsa.pubkey.point
            return (hex(pub_point.x()), hex(pub_point.y()))
        elif keytype == "ed25519":
            # (x) of the Ed25519 curve point
            return int.from_bytes(self._decoded_key, "big")
        elif keytype == "rsa":
            # (e,n)
            pub_numbers = self.rsa.public_numbers()
            return (hex(pub_numbers.e), hex(pub_numbers.n))
        else:
            raise Exception("Invalid key type, must be rsa, ecdsa or ed25519")

    def get_fingerprint(self):
        fg_computed = self.hash_sha256()
        fg_header = "SHA256:"
        if not fg_computed.startswith(fg_header):
            raise Exception("Error during fingerprint computation")
        return fg_computed[len(fg_header) :]


class SSHhost:
    def __init__(self, domain, infos):
        self.domain = domain
        self.info_url = infos["info-url"]
        self.keys = {}
        type_info = infos["info-provided"]
        for key in infos["keys"]:
            print(f"  - Adding {key['type']} key {key['params']}")
            if key["type"] in self.keys:
                raise Exception("Keytype already prensent for this host")
            if type_info == "SSHPubKey":
                key["pubkey"] = key["data"]
                self.keys[key["type"]] = HostKey(key)
                if not self.check_key_from_server(key["type"]):
                    raise Exception("Key read from server invalid or error")
            elif type_info == "fingerprint":
                kfingerprint = key["data"]
                if len(kfingerprint) != 43:  # To Do regex b64 43 chars
                    raise Exception("Invalid fingerprint string format")
                key["pubkey"] = self.get_server_publickey(key["type"])
                current_keyobj = HostKey(key)
                self.keys[key["type"]] = current_keyobj
                if current_keyobj.get_fingerprint() != kfingerprint:
                    raise Exception("Key read from server has a different fingerprint")
            else:
                raise Exception("Invalid key type, must be SSHPubKey or fingerprint")
            print("    OK : key checked and added")

    def get_server_publickey(self, key_type):
        print("    reading current host public key ...")
        resp = subprocess.run(
            f"ssh-keyscan -4 -t {key_type} {self.domain}",
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        key_strings = resp.stdout.decode("ascii").rstrip().split(" ")
        if len(key_strings) != 3:
            raise "Bad response from system or server"
        return key_strings[2]

    def check_key_from_server(self, key_type):
        return self.get_server_publickey(key_type) == self.keys[key_type].pkdata

    def write_key_line(self, key_type):
        current_keyobj = self.keys[key_type]
        return f"{self.domain} {current_keyobj.keytype_id} {current_keyobj.pkdata}\n"

    def write_knownhosts_lines(self, fileout):
        for key in self.keys:
            fileout.write(self.write_key_line(key))
