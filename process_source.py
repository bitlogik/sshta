# Process source for SSH Trusted Authority
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


import datetime
import json
from SSHhosts import SSHhost


DIRECTORY = "../"
SOURCE_FILE = "source.json"
DATA_FILE = "data.json"
HOSTS_FILE = "known_hosts"

OUTPUT_WIDTH = 64
print("#" * OUTPUT_WIDTH)
print("SSH Trusted Authority".center(OUTPUT_WIDTH))
print("#" * OUTPUT_WIDTH)

print(
    "Script started on :",
    datetime.datetime.utcnow().strftime("%b %d %Y at %H:%M:%S UTC"),
)

# Load source infos
fsource = open(DIRECTORY + SOURCE_FILE, "r")
data_source = json.load(fsource)
fsource.close()

print("")

# Load and check all info
servers = []
for domain, datainfos in data_source.items():
    print(f"Public host : {domain}")
    try:
        ssh_host = SSHhost(domain, datainfos)
    except Exception as exc:
        print("    ERROR : host not added :", exc)
        print("")
    else:
        servers.append(ssh_host)
        print(" Host added\n")


# Build hosts data object for JSON
# List of public keys
hosts_data = []
for serv in servers:
    for ky in serv.keys:
        current_pubkey = {}
        current_pubkey["service"] = serv.domain
        current_pubkey["type"] = "Ed25519" if ky == "ed25519" else ky.upper()
        current_pubkey["params"] = serv.keys[ky].params
        current_pubkey["pubkey"] = serv.keys[ky].get_key_values(ky)
        current_pubkey["fingerprint"] = f"SHA256:{serv.keys[ky].get_fingerprint()}"
        current_pubkey["SSHdataPubKey"] = serv.keys[ky].get_sshformat_data()
        hosts_data.append(current_pubkey)


# Save in hosts data file
with open(DIRECTORY + DATA_FILE, "w") as data_file:
    json.dump(hosts_data, data_file, indent=2)
print("data.json file written\n")


# Build the known hosts file from processed data
with open(DIRECTORY + HOSTS_FILE, "w", newline="\n") as knownhost_file:
    for servi in servers:
        servi.write_knownhosts_lines(knownhost_file)
print("knonw_hosts file written\n")


print("Finished on :", datetime.datetime.utcnow().strftime("%b %d %Y at %H:%M:%S UTC"))
