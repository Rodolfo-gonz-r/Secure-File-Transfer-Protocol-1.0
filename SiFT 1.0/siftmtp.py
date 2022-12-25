#python3

import socket
import sys
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto import Random
import getpass

class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.msg_hdr_rsv = b'\x00\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.size_msg_mac = 12
		self.size_msg_etk = 256
		self.size_transfer_key = 32
		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = (self.type_login_req, self.type_login_res, 
						  self.type_command_req, self.type_command_res,
						  self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
						  self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
		# --------- STATE ------------
		self.peer_socket = peer_socket
		self.snd_sqn = 0
		self.rcv_sqn = 0
		self.transfer_key = None 


	# sets the value of the transfer key and changes state to initialized
	def set_transfer_key(self, key):
		self.transfer_key = key


	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i+self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]
		return parsed_msg_hdr


	# parses a message body of a given msg type and returns a dictionary containing the body parts
	def parse_msg_body(self, msg_type, msg_body):

		parsed_msg_body, i = {}, len(msg_body)
		if msg_type == self.type_login_req:
			parsed_msg_body['etk'], i = msg_body[i-self.size_msg_etk:i], i-self.size_msg_etk 
		parsed_msg_body['mac'], i = msg_body[i-self.size_msg_mac:i], i-self.size_msg_mac 
		parsed_msg_body['epd'] = msg_body[:i] 
		return parsed_msg_body


	# receives n bytes from the peer socket
	def receive_bytes(self, n):
		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received


	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		if not self.transfer_key:
			raise SiFT_MTP_Error('Transfer key is not yet established')

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		parsed_msg_body = self.parse_msg_body(parsed_msg_hdr['typ'], msg_body)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(parsed_msg_body['epd'])) + '): ' + parsed_msg_body['epd'].hex())
			print('MAC (' + str(len(parsed_msg_body['mac'])) + '): ' + parsed_msg_body['mac'].hex())
			print('------------------------------------------')
		# DEBUG 

		msg_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')

		if msg_sqn <= self.rcv_sqn:
			raise SiFT_MTP_Error('Unexpected message sequence number found')

		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		cipher.update(msg_hdr)

		try:
			msg_payload = cipher.decrypt_and_verify(parsed_msg_body['epd'], parsed_msg_body['mac'])
		except (ValueError, KeyError):
			raise SiFT_MTP_Error('Decryption or MAC verification failed')

		# if message received successfully
		self.rcv_sqn = msg_sqn

		return parsed_msg_hdr['typ'], msg_payload


	# receives and parses a login_req message using the provided private key, returns msg_type and msg_payload
	def receive_login_req(self, privkey):
		# print("PRIVJIN")

		if self.transfer_key:
			raise SiFT_MTP_Error('Transfer key is already established')

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] != self.type_login_req:
			raise SiFT_MTP_Error('Unexpected message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		if len(msg_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body received')

		parsed_msg_body = self.parse_msg_body(parsed_msg_hdr['typ'], msg_body)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(parsed_msg_body['epd'])) + '): ' + parsed_msg_body['epd'].hex())
			print('MAC (' + str(len(parsed_msg_body['mac'])) + '): ' + parsed_msg_body['mac'].hex())
			print('ETK (' + str(len(parsed_msg_body['etk'])) + '): ' + parsed_msg_body['etk'].hex())
			print('------------------------------------------')
		# DEBUG 

		msg_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
		
		if msg_sqn <= self.rcv_sqn:
			raise SiFT_MTP_Error('Unexpected message sequence number found')
		print(parsed_msg_body['etk'])
		try:
			RSAcipher = PKCS1_OAEP.new(privkey)
			tmp_key = RSAcipher.decrypt(parsed_msg_body['etk'])
			# DEBUG 
			if self.DEBUG:
				print("Temporary key: " + tmp_key.hex())
			# DEBUG 
		except (ValueError, KeyError):
			raise SiFT_MTP_Error('Decryption of temporary transfer key failed')

		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']
		cipher = AES.new(tmp_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		cipher.update(msg_hdr)

		try:
			msg_payload = cipher.decrypt_and_verify(parsed_msg_body['epd'], parsed_msg_body['mac'])
		except (ValueError, KeyError):
			raise SiFT_MTP_Error('Decryption or MAC verification failed')

		# if message received successfully
		self.rcv_sqn = msg_sqn

		return parsed_msg_hdr['typ'], msg_payload, tmp_key


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		
		if not self.transfer_key:
			raise SiFT_MTP_Error('Transfer key is not yet established')

		# build message
		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr_sqn = (self.snd_sqn+1).to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		msg_hdr_rnd = get_random_bytes(self.size_msg_hdr_rnd)
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd + self.msg_hdr_rsv
		nonce = msg_hdr_sqn + msg_hdr_rnd
		cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		cipher.update(msg_hdr)
		msg_epd, msg_mac = cipher.encrypt_and_digest(msg_payload)

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('EPD (' + str(len(msg_epd)) + '): ' + msg_epd.hex())
			print('MAC (' + str(len(msg_mac)) + '): ' + msg_mac.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(msg_hdr + msg_epd + msg_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

		# if message sent successfully
		self.snd_sqn += 1


	# builds and sends a login_req message using the provided payload and public key
	def send_login_req(self, msg_payload, pubkey):
    		
		# build message
		
		#msg_payload is the middle payload part. we need to encrypt this. 
		#the header needs to be built using the different components of it - the size is in the top of this file
		#the content of each of the components of the header comes from the specification so build the header
		#c
		#msghdr: |  ver  |  typ  |  len  |  sqn  |          rnd          |  rsv  |
		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac + self.size_msg_etk
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr_sqn = (self.snd_sqn+1).to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		msg_hdr_rnd = Random.get_random_bytes(self.size_msg_hdr_rnd)
  
		msg_hdr = self.msg_hdr_ver + self.type_login_req + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd + self.msg_hdr_rsv  		


		#generating random aes key
		random_key = Random.get_random_bytes(self.size_transfer_key)
  #encryption happens here aes in gcm mode - using random key (etk)
		nonce = msg_hdr_sqn + msg_hdr_rnd
		cipher = AES.new(random_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)
		cipher.update(msg_hdr)
		msg_epd, msg_mac = cipher.encrypt_and_digest(msg_payload)
  
		# etk should be encrypted pubkey
		# rsa encrypt the random_key with the servers public key here
  
		# create an RSA cipher object
		# pubkey = self.load_publickey()
		RSAcipher = PKCS1_OAEP.new(pubkey)
		# print(pubkey)
		# print(self.load_keypair())
		#encrypt the AES key with the RSA cipher
		e_tmp_key = RSAcipher.encrypt(random_key)
		# print(len(tmp_key))
     
     		# DEBUG
		if self.DEBUG:
			print('MTP login request to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ' + msg_payload.hex())
			print('Sequence number after sending login request: ', msg_hdr_sqn)
			print('------------------------------------------')
		# DEBUG
		# print(tmp_key)
		# try to send
#we need create the entire message by concat the msg hdr+enc_payload+mac+tmp_key. we need to send this over.
		try:
			self.send_bytes(msg_hdr + msg_epd + msg_mac + e_tmp_key)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

		# if message sent successfully
		self.snd_sqn += 1

		return random_key


	# loads the server's public key from the file `pubkey.pem` residing in the current directory
	def load_publickey(self):
		pubkeyfile = 'pubkey.pem'
		with open(pubkeyfile, 'rb') as f:
			pubkeystr = f.read()
		try:
			return RSA.import_key(pubkeystr)
		except ValueError:
			print('Error: Cannot import public key from file ' + pubkeyfile)
			sys.exit(1)
   
   
	def load_keypair(self):
		privkeyfile = "privkey.pem"
		# passphrase = 'ait-budapest'
		passphrase = getpass.getpass('Enter a passphrase to load the server private key: ')
		with open(privkeyfile, 'rb') as f:
			keypairstr = f.read()
		try:
			return RSA.import_key(keypairstr, passphrase=passphrase)
		except ValueError:
			print('Error: Cannot import private key from file ' + privkeyfile)
			sys.exit(1)