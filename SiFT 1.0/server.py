#python3

import sys
import threading
import socket
import getpass
from Crypto.PublicKey import RSA
from siftmtp import SiFT_MTP, SiFT_MTP_Error
from siftlogin import SiFT_LOGIN, SiFT_LOGIN_Error
from siftcmd import SiFT_CMD, SiFT_CMD_Error

class Server:
    def __init__(self):
        # ------------------------ CONFIG -----------------------------
        self.server_privkeyfile = 'privkey.pem'
        #TODO
        # self.server_pubkeyfile = 'pubkey.pem'
        self.server_usersfile = 'users.txt' 
        self.server_usersfile_coding = 'utf-8'
        self.server_usersfile_rec_delimiter = '\n'
        self.server_usersfile_fld_delimiter = ':'
        self.server_rootdir = './users/'
        # self.server_ip = socket.gethostbyname(socket.gethostname())
        self.server_ip = socket.gethostbyname('localhost')
        self.server_port = 5150
        # -------------------------------------------------------------
        self.server_keypair = self.load_keypair(self.server_privkeyfile)
        # self.server_keypair = self.load_publickey(self.server_pubkeyfile)
        self.server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        self.server_socket.bind((self.server_ip, self.server_port))
        self.server_socket.listen(5)
        print('Listening on ' + self.server_ip + ':' + str(self.server_port))
        self.accept_connections()

    def load_keypair(self, privkeyfile):
            passphrase = getpass.getpass('Enter a passphrase to load the server private key: ')
            with open(privkeyfile, 'rb') as f:
                keypairstr = f.read()
            try:
                return RSA.import_key(keypairstr, passphrase=passphrase)
            except ValueError:
                print('Error: Cannot import private key from file ' + privkeyfile)
                sys.exit(1)

    # #TODO
    # def load_publickey(self, pubkeyfile):
    #         # pubkeyfile = 'publickey.pem'
    #         with open(pubkeyfile, 'rb') as f:
    #             pubkeystr = f.read()
    #         try:
    #             return RSA.import_key(pubkeystr)
    #         except ValueError:
    #             print('Error: Cannot import public key from file ' + pubkeyfile)
    #             sys.exit(1)
            
    
    

    def load_users(self, usersfile):
        users = {}
        with open(usersfile, 'rb') as f:
            allrecords = f.read().decode(self.server_usersfile_coding)
        records = allrecords.split(self.server_usersfile_rec_delimiter)
        for r in records:
            fields = r.split(self.server_usersfile_fld_delimiter)
            username = fields[0]
            usr_struct = {}
            usr_struct['pwdhash'] = bytes.fromhex(fields[1])
            usr_struct['icount'] = int(fields[2])
            usr_struct['salt'] = bytes.fromhex(fields[3])
            usr_struct['rootdir'] = fields[4]
            users[username] = usr_struct
        return users


    def accept_connections(self):
        while True:
            client_socket, addr = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, addr, )).start()


    def handle_client(self, client_socket, addr):
        print('New client on ' + addr[0] + ':' + str(addr[1]))

        mtp = SiFT_MTP(client_socket)

        loginp = SiFT_LOGIN(mtp)
        loginp.set_server_keypair(self.server_keypair)
        #loginp.set_server_pubkey(self.server_pubkey)
        users = self.load_users(self.server_usersfile)
        loginp.set_server_users(users)

        try:
            user = loginp.handle_login_server()
        except SiFT_LOGIN_Error as e:
            print('SiFT_LOGIN_Error: ' + e.err_msg)
            print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
            #client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
            return

        cmdp = SiFT_CMD(mtp)
        cmdp.set_server_rootdir(self.server_rootdir)
        cmdp.set_user_rootdir(users[user]['rootdir'])

        while True:
            try:
                cmdp.receive_command()
            except SiFT_CMD_Error as e:
                print('SiFT_CMD_Error: ' + e.err_msg)
                print('Closing connection with client on ' + addr[0] + ':' + str(addr[1]))
                #client_socket.shutdown(socket.SHUT_RDWR)
                client_socket.close()
                return


# main
if __name__ == '__main__':
    server = Server()