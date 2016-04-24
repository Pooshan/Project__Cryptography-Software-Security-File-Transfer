import socket
import doctest
from itertools import izip, cycle
import itertools
import base64
import binascii
import struct
import sys
from Crypto.Cipher import AES
import random
import hashlib
import os


def Main():
    host = 'localhost'
    # port = raw_input("Enter port number: ")
    # port = int(port)
    port = 4000

    s = socket.socket()
    s.connect((host, port))

    count = 0

    #DH PARAMETERS
    p = 197221152031991558322935568090317202983
    g = 2
    # client_secret = 197221152031991558322935568097826974661
    client_secret = 4597

    print '\n ------------------ Step 1 ----------------------- '

    message = raw_input("Enter Username->")
    while message != 'q':
        s.send(message)
        data = s.recv(1024)
        print "Received from server: " + str(data)
        if str(data) == 'u_ack':
            password = raw_input("Enter Password ->")
            print password
            s.send(password)
            decision = s.recv(1024)
            if str(decision) == 'Authenticated':
                print "User Authenticated"
                # mod_1 = (g**client_secret) % p
                # mod_1 = (2**4) % 6 #for testing small numbers
                mod_1 = modlargeNum(g, client_secret, p)
                print "mod 1 : ",mod_1
                print 'sizeof(mod_1)', sys.getsizeof(mod_1)

                print '\n ------------------ Step 2 ----------------------- '

                print "----------Starting the real SECURE Communication-----------"

                # ---------------XOR STARTS--------------

                # xor_1 = strxor(str(mod_1), password)
                password = password.ljust(39, '0')
                print 'password', password
                #XOR converts STRING to DECIMAL and returns CHAR
                xor_test = xor_message(str(mod_1), password)
                # pw_bin = ' '.join(format(ord(x), 'b') for x in password)
                # print pw_bin, mod_1

                # ---------------XOR ENDS--------------

                print "XORed message: ", xor_test

                # ------------TESTING SHIT STARTS---------------
                # new_xor = xor_strings(str(mod_1), password)
                # print "NEW XOR message: ", new_xor
                # xor_decrypt = xor_message(xor_test, password)
                # print "XOR decrypt : ", xor_decrypt
                # ------------TESTING SHIT ENDS---------------

                #-------FROM CHR TO HEX BELOW
                # xored_hex = "".join("{:02x}".format(ord(c)) for c in xor_test)
                # print xored_hex

                s.sendall(str(p)) # sending p to server

                pConf = s.recv(1024)
                if pConf == 'pAck':
                    print "P sent"
                    s.sendall(str(g)) # sending g to server

                gConf = s.recv(1024)
                if gConf == 'gAck':
                    print "g sent"
                    s.sendall(str(xor_test))

                xorConf = s.recv(1024)
                if xorConf == 'xorAck':
                    print "Client XOR Transferred"

                print "P G and XOR message sent to server"

                print '\n ------------------ Step 3 ----------------------- '

                # s.send(str(xored_hex)) # sending xored hex to server

                # ---------------------------------------------------
                # ----------------MESSAGE 1 ENDS HERE----------------
                # ---------------------------------------------------

                # --------------From Server Starts MESSAGE 2-------------
                # while 1:
                #   xored_server = s.recv(1024)
                #   if not xored_server:
                #       break

                    # if not aes_server_cipertext:
                    #   break

                xored_server = s.recv(1024)
                s.sendall('xorServerAck')
                print "xor server received"

                aes_server_cipertext = s.recv(1024)
                s.sendall('aesAck')
                print "aes server received"
                # xored_server = recv_msg(s)
                # aes_server_cipertext = recv_msg(s)
                print 'xored_server', xored_server
                print "AES: ", aes_server_cipertext

                # --------------From Server Ends---------------

                decryptServerXor = xor_message(xored_server, password)
                print "Dec server XOR g^(Xs) : ", decryptServerXor
                encryptServerXor = xor_message(decryptServerXor, password)
                print "Match with Server XOR : ", encryptServerXor
                decryptServerXor = int(decryptServerXor)
                keyKas = modlargeNum(decryptServerXor, client_secret, p)
                print "\n ------------------ Kas Key : ---------------------- ", keyKas  #returns INT
                newKas = str(keyKas)[:32]
                print '\n newKas', newKas

                print '\n -- Kas match both side client and server, hence we perform the right opration and it is correct result ---\n '

                # ---------------------------------------------------
                # ----------------MESSAGE 2 ENDS HERE----------------
                # ---------------------------------------------------

                print '\n ------------------ Step 4 ----------------------- '

                print ' \n------------AES DECRYPTION STARTS-----------'

                IV = 16 * '\x00'           # Initialization vector: discussed later
                mode = AES.MODE_CBC
                decryptor = AES.new(newKas, mode, IV=IV)
                nonce_Ns = decryptor.decrypt(aes_server_cipertext)
                print nonce_Ns, type(nonce_Ns)

                # ------------AES DECRYPTION ENDS-----------

                # Generating Nonce Na below
                # nonce_Na = generate_nonce() # returns STR
                nonce_Na = '11000110001100011000000000000000'
                #print "Client NONCE Na : ", nonce_Na
                print "Nonce is the text for AES"

                # Concatenationg Nonces, Na and Ns
                concatenationNonce = nonce_Na + nonce_Ns
                #print "Nonce concatenation Na||Ns : ", concatenationNonce

                # ------------AES ENCRYPTION STARTS-----------

                encryptor = AES.new(newKas, mode, IV=IV)
                ciphertext = encryptor.encrypt(concatenationNonce)
                #print "AES Cipher Text at Client: ", ciphertext

                # ------------AES ENCRYPTION ENDS-----------

                s.sendall(ciphertext)
                aesClientConf = s.recv(1024)
                if aesClientConf == 'clientAesAck':
                    print "Message 3 Transfer Success"

                # ---------------------------------------------------
                # ----------------MESSAGE 3 ENDS HERE----------------
                # ---------------------------------------------------

                s.sendall('send_aes_nonceNa')
                aes_nonce_Na_cipher = s.recv(1024)
                # s.sendall('aesNonceNaAck')
                #print "AES of Nonce Na from Server : ", aes_nonce_Na_cipher
                print "Message 4 Received"

                # ---------------------------------------------------
                # ----------------MESSAGE 4 ENDS HERE----------------
                # ---------------------------------------------------

                print '\n ------------------ Step 5 ----------------------- '

                # -----------------MESSAGE 5 START----------------------------

                print ' \n -------------Secure FILE TRANSFER STARTS---------------'

                # length = s.recv(4)
                length = s.recv(16)
		s.sendall('LnACK')

                size = int(length)
                current_size = 0
                buffer = b""
		ctsFile = s.recv(1024)
		if ctsFile == 'ok':
		        while current_size < size:
		            data = s.recv(1024)
		            if not data:
		                break
		            if len(data) + current_size > size:
		                data = data[:size - current_size]  # trim additional data
		            buffer += data
		            # you can stream here to disk
		            current_size += len(data)
		            # you have entire file in memory

                #print '\n ------- File received from Server, START HERE-------- \n \n ', buffer

                print '\n ------- File received from Server, END HERE-------- '

                print '\n ------ File Successfully Received ------- '
                s.send('File delivered')

                # -------------FILE TRANSFER ENDS----------------

                # -------------SHA1 START------------------------

                hash_object = hashlib.sha1(buffer)
                hex_dig = hash_object.hexdigest()
                print '\n Client SHA1 of this file is: ', hex_dig
                serSHA1 = s.recv(1024)
                print '\n Server SHA1 of this file is: ', serSHA1

                # -------------SHA1 ENDS--------------------------

                if hex_dig == serSHA1:
                    print ' \n ------ Integrity report: File integrity is intact :) ------ '
                else:
                    print ' \n ----- Hey! CAUTION!: File is corrupt and may be altered. ----- '
                    print ' Advise: request new file --- you have max 3 attempts to get file '
                break
            else:
                print "User NOT Authenticated"
                count += 1
                # password = raw_input("Try Again ->")
        else:
            print "WRONG username..."
            count += 1
        if count < 3:
            message = raw_input("Try Again Username ->")
        if count == 3:
            print "ACCESS DENIED"
            break
    # ------------Username and Password ENDS----------------

    s.close()

# --------------------FUCTIONS / METHODS ------------------------------------


def generate_nonce(length=16):
    # """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

def recv_msg(sock):
    # Read message length and unpack it into an integer
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]
    # Read the message data
    return recvall(sock, msglen)

def recvall(sock, n):
    # Helper function to recv n bytes or return None if EOF is hit
    data = ''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
        return data


def xor_strings(s,t):
    """xor two strings together"""
    return "".join(chr(ord(a)^ord(b)) for a,b in zip(s,t))

def modlargeNum(base,power,p):
    if power ==0:
        return 1
    if power % 2 ==0:
        tmp=modlargeNum(base,power/2,p)
        return (tmp * tmp) % p
    else:
        return (base * modlargeNum(base,power-1,p)) % p

def xor_message(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def recvFunc(self, msgLen):
        msg = ""
        bytesRcvd = 0
        while bytesRcvd < msgLen:
            chunk = self.s.recv(msgLen - bytesRcvd)

            if chunk == "": break

            bytesRcvd += len(chunk)
            msg       += chunk

            if string.find(msg, "\n"): break
        return msg

# -------------------Main()-------------------

if __name__ == '__main__':
    doctest.testmod(verbose = True)
    Main()
