import socket
import doctest
from Crypto.Cipher import AES
import random
import sys
import struct
import hashlib
import os


def Main():
    host = 'localhost'
    # port = raw_input("Enter port number: ")
    # port = int(port)
    port = 4000

    s = socket.socket()
    s.bind((host, port))

    s.listen(1)
    c, addr = s.accept()
    print "Connection from: " + str(addr)

    while True:
        data = c.recv(1024)
        if not data:
            print "----- END OF SESSION, BYE! ------"
            break

        print '\n ------------------ Step 1 ----------------------- '

        print "from connected user: " + str(data)

        print '\n ------------Username and Password----------------'

        if str(data) == 'yash101' or 'pooshan101':
            client_id = str(data)
            print client_id     # getting client ID
            c.send('u_ack')
            password = c.recv(1024)
            if str(password) == 'niceday':
                c.send('Authenticated')

                p = c.recv(1024)    # getting p
                c.send('pAck')
                print " P received "
                p = int(p)

                g = c.recv(1024)    # getting g
                c.send('gAck')
                print "G received"
                g = int(g)

                xored_client = c.recv(1024) # getting xor of client
                c.send('xorAck')
                print "Xor client received"

                # xored_client = xored_client
                print '\n ------ Value of P : --------', p, g,
                print '\n ------ Value of g : --------', g
                print '\n ------ Value of xored_client : --------', xored_client
                # server_secret = 197443274309234702374320493274939487257
                server_secret = 5516
                password = password.ljust(39, '0')
                print ' Password:  ', password

                print '\n ------------------ Step 2 ----------------------- '

                # ---------------MOD STARTS--------------

                mod_serverDH = modlargeNum(g, server_secret, p)
                print "mod_serverDH g^Xs mod p : ", mod_serverDH

                # ---------------MOD STARTS--------------

                # ---------------XOR STARTS--------------

                xorWithPass = xor_message(str(mod_serverDH), password)
                print "XORed with Password : ", xorWithPass # returns char - M2 SEND TO CLIENT
                xored_hex_server = "".join("{:02x}".format(ord(c)) for c in xorWithPass)
                print 'xored_hex_server', xored_hex_server # returns HEX

                # ---------------XOR ENDS--------------

                print ' \n ---------------XOR DECRYPT and ENCRYPT-------------- '

                decryptClientXor = xor_message(xored_client, password)
                print "dec client XOR G^xa: ", decryptClientXor #returns CHAR
                encryptAgain = xor_message(decryptClientXor, password)
                print "Match with client XOR : ", encryptAgain  #returns CHAR
                print "Key Kas is g^(XaXs) mod p"
                keyKas = modlargeNum(int(decryptClientXor), server_secret, p)
                print " ---------------- Kas KEY : --------------", keyKas  #returns INT

                # ---------------ENDS--------------

                # nonce_Ns = generate_nonce() # returns STR
                nonce_Ns = '11100111011100111000000000000000'
                print "Server NONCE : ", nonce_Ns
                print "Nonce is the text for AES", type(nonce_Ns)

                print '\n ------------------ Step 3 ----------------------- '

                print '\n ---------------AES STARTS-------------- '

                # KEY and TEXT have to be STR format to perform AES
                key = '49327493294327478947847328894738' # 16 byte key for AES(128)

                print '\n --- Kas match both side client and server, hence we perform the right opration and it is correct result ---\n '

                newKas = str(keyKas)[:32]
                # newKas = int(newKas)
                # print "NEW KAS", (newKas)
                # print sys.getsizeof(key)
                # print sys.getsizeof('82395155117150893193249167212321992151')
                # key = '42394503760154450521289873942225720466'
                print "Key in DECIMAL", int(newKas)
                IV = 16 * '\x00'           # Initialization vector: discussed later
                mode = AES.MODE_CBC
                encryptor = AES.new(newKas, mode, IV=IV)
                # text below is nothing but server_secret in string format
                # text = '3476576834593040621903216239480246234712872104970004097324072013'
                ciphertext = encryptor.encrypt(nonce_Ns)
                print "AES Cipher Text: ", ciphertext #returns CHAR - M2 SEND TO CLIENT
                # print "in HEX : ", "".join("{:02x}".format(ord(c)) for c in ciphertext) #CHAR to HEX
                # print int("".join("{:02x}".format(ord(c)) for c in ciphertext), 16) #Hex to Dec

                # ---------------AES ENDS--------------

                print 'sizeof(xorWithPass)', sys.getsizeof(xorWithPass)
                print 'sizeof(ciphertext)', sys.getsizeof(ciphertext)
                # c.send('message2')
                c.sendall(xorWithPass)
                xorConf = c.recv(1024)
                if xorConf == 'xorServerAck':
                    print "Server XOR Sent"
                    c.sendall(ciphertext)
                aesConf = c.recv(1024)
                if aesConf == 'aesAck':
                    print "XOR and AES transferred successfully"

                print '\n ------------------ Step 4 ----------------------- '

                # ---------------------------------------------------
                # ----------------MESSAGE 2 ENDS HERE----------------
                # ---------------------------------------------------

                aes_client_ciphertext = c.recv(1024)
                c.send('clientAesAck')
                print "aes_client_ciphertext received: ", aes_client_ciphertext

                # ---------------------------------------------------
                # ----------------MESSAGE 3 ENDS HERE----------------
                # ---------------------------------------------------

                # ------------AES DECRYPTION STARTS-----------

                # below was received from client
                decryptor = AES.new(newKas, mode, IV=IV)
                concatenatedNonceFromClient = decryptor.decrypt(aes_client_ciphertext)
                print 'concatenatedNonceFromClient', concatenatedNonceFromClient

                # ------------AES DECRYPTION ENDS-----------

                #Splitting the Nonce Na||Ns done at Client
                #Retrieving Nonce Na
                split_nonce_Na = concatenatedNonceFromClient[:16]
                print "Split Recovered Nonce Na : ", split_nonce_Na

                # ------------AES ENCRYPTION STARTS-----------

                encryptor = AES.new(newKas, mode, IV=IV)
                ciphertext_Na = encryptor.encrypt(split_nonce_Na)
                print "AES Na cipher at Server: ", ciphertext_Na

                # ------------AES ENCRYPTION ENDS-----------

                # ------Sending the Nonce Na ciphertext to Client-----

                print '\n ------------------ Step 4 ----------------------- '

                clear_to_send_Na_AES = c.recv(1024)
                if clear_to_send_Na_AES == 'send_aes_nonceNa':
                    c.sendall(ciphertext_Na)

                # aesServerNonceNaConf = c.recv(1024)
                # if aesServerNonceNaConf == 'aesNonceNaAck':
                print "Message 4 Transfer Success"

                # ---------------------------------------------------
                # ----------------MESSAGE 4 ENDS HERE----------------
                # ---------------------------------------------------

                # -----------------MESSAGE 5 START----------------------------

                print ' \n -------------Secure FILE TRANSFER STARTS---------------'

                print '\n ------------------ Step 5 ----------------------- '

                fileSentCount = 0

                if fileSentCount < 3:
                    if os.path.exists('testfile1.pdf'):
                        length = os.path.getsize('testfile1.pdf')  # get file size in bytes
                        c.send(str(length))  # has to be 4 bytes

		len_sent = c.recv(1024)
		if len_sent == 'LnACK':
		    c.sendall('ok')			
                    filename = 'testfile1.pdf'
                    f = open(filename, 'rb')
                    l = f.read(1024)
                    while (l):
                        c.sendall(l)
                        #print('Sent ', repr(l))
                        l = f.read(1024)
                    f.close()
                    fileSentCount += 1
                    print 'File sent!'

                    # -------------FILE TRANSFER ENDS------------------

                    # -------------ADDITIONAL FILE TRANSFER REQUEST----

                    confi = c.recv(1024)
                    if confi == 'File delivered':
                        print 'File delivered'
                    elif fileSentCount < 3:
                        if os.path.exists('testfile1.pdf'):
                            length = os.path.getsize('testfile1.pdf')  # get file size in bytes
                            c.send(str(length))  # has to be 4 bytes

                        filename = 'testfile1.pdf'
                        f = open(filename, 'rb')
                        l = f.read(1024)
                        while (l):
                            c.sendall(l)
                            print('Sent ', repr(l))
                            l = f.read(1024)
                        f.close()
                        fileSentCount += 1
                        print 'File sent!'
                    else:
                        print 'Sorry!, You have reached Max limit to request same file. '

                    print '\n -------------SHA1 START------------------------'
                    def sha1ofFile(helpMe):
                        sha = hashlib.sha1()
                        with open(helpMe, 'rb') as f:
                            while True:
                                block = f.read(2 ** 10)  # Magic number: one-megabyte blocks (1 MB = 1024).
                                if not block: break
                                sha.update(block)
                            # print sha.hexdigest()
                            return sha.hexdigest()

                    # -------------SHA1 ENDS--------------------------

                    sha1ofFile('testfile1.pdf')

                    print 'SHA1 of server file is: ', sha1ofFile('testfile1.pdf')

                    fileSHA1 = sha1ofFile('testfile1.pdf')
                    c.send(fileSHA1)

            else:
                c.send('Not Authenticated')
        else:
            c.send('Wrong Username')

        # """------------Username and Password ENDS----------------"""

    c.close()


# --------------------FUCTIONS / METHODS ------------------------------------

def send_msg(sock, msg):
    # Prefix each message with a 4-byte length (network byte order)
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)

def generate_nonce(length=16):
    # """Generate pseudorandom number."""
    return ''.join([str(random.randint(0, 9)) for i in range(length)])

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

def convert_to_bytes(no):
    result = bytearray()
    result.append(no & 255)
    for i in range(3):
        no = no >> 8
        result.append(no & 255)
    return result

# -------------------Main()-------------------

if __name__ == '__main__':
    doctest.testmod(verbose = True)
    Main()
