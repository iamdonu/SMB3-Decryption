import hashlib
import hmac
import argparse

# Stolen from impacket. Thank you all for your wonderful contributions to the community
try:
    from Cryptodome.Cipher import ARC4
    from Cryptodome.Cipher import DES
    from Cryptodome.Hash import MD4
except Exception:
    print("Warning: You don't have any crypto installed. You need pycryptodomex")
    print("See https://pypi.org/project/pycryptodomex/")

def generateEncryptedSessionKey(keyExchangeKey, exportedSessionKey):
    cipher = ARC4.new(keyExchangeKey)
    sessionKey = cipher.encrypt(exportedSessionKey)
    return sessionKey

###

parser = argparse.ArgumentParser(description="Calculate the Random Session Key based on data from a PCAP (maybe).")
parser.add_argument("-u", "--user", required=True, help="User name")
parser.add_argument("-d", "--domain", required=True, help="Domain name")
parser.add_argument("-p", "--password", required=True, help="Password of User")
parser.add_argument("-n", "--ntproofstr", required=True, help="NTProofStr. This can be found in PCAP")
parser.add_argument("-k", "--key", required=True, help="Encrypted Session Key. This can be found in PCAP")
parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")

args = parser.parse_args()

# Upper Case User and Domain
user = str(args.user).upper().encode('utf-16le')
domain = str(args.domain).upper().encode('utf-16le')

# Create 'NTLM' Hash of password
passw = args.password.encode('utf-16le')
hash1 = hashlib.new('md4', passw)
password = hash1.digest()

# Calculate the ResponseNTKey
h = hmac.new(password, digestmod=hashlib.md5)
h.update(user + domain)
respNTKey = h.digest()

# Use NTProofSTR and ResponseNTKey to calculate Key Exchange Key
NTproofStr = bytes.fromhex(args.ntproofstr)
h = hmac.new(respNTKey, digestmod=hashlib.md5)
h.update(NTproofStr)
KeyExchKey = h.digest()

# Calculate the Random Session Key by decrypting Encrypted Session Key with Key Exchange Key via RC4
RsessKey = generateEncryptedSessionKey(KeyExchKey, bytes.fromhex(args.key))

if args.verbose:
    print("USER WORK: " + user.decode('utf-16le') + domain.decode('utf-16le'))
    print("PASS HASH: " + password.hex())
    print("RESP NT:   " + respNTKey.hex())
    print("NT PROOF:  " + NTproofStr.hex())
    print("KeyExKey:  " + KeyExchKey.hex())
print("Random SK: " + RsessKey.hex())
