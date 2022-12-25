import time
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Random import get_random_bytes
from siftmtp import SiFT_MTP, SiFT_MTP_Error
from Crypto import Random

import socket
import sys
from Crypto.Cipher import AES, PKCS1_OAEP
import getpass


def load_keypair():
		privkeyfile = "privkey.pem"
		passphrase = 'ait-budapest'
		# passphrase = getpass.getpass('Enter a passphrase to load the server private key: ')
		with open(privkeyfile, 'rb') as f:
			keypairstr = f.read()
		try:
			return RSA.import_key(keypairstr, passphrase=passphrase)
		except ValueError:
			print('Error: Cannot import private key from file ' + privkeyfile)
			sys.exit(1)

def load_publickey():
		pubkeyfile = 'pubkey.pem'
		with open(pubkeyfile, 'rb') as f:
			pubkeystr = f.read()
		try:
			return RSA.import_key(pubkeystr)
		except ValueError:
			print('Error: Cannot import public key from file ' + pubkeyfile)
			sys.exit(1)

privkey = load_keypair()

pubkey = load_publickey()

random_key = Random.get_random_bytes(32)
print(sizeof(pubkey))
#print(pubkey)

RSAcipher = PKCS1_OAEP.new(pubkey)

tmp_key = RSAcipher.encrypt(random_key)

RSAcipher = PKCS1_OAEP.new(privkey)

tmp_key = RSAcipher.decrypt(tmp_key)

#print(tmp_key)

