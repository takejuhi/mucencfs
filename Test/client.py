from __future__ import print_function, with_statement

import socket
import ssl
import time

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA1

IP = "localhost"
PORT = 4433

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
with open("Client/someone_pri_key.pem",'rb') as f:
  pri_key = RSA.import_key(f.read())

def decrypt(data):
  return PKCS1_OAEP.new(pri_key, SHA1).decrypt(data).decode('utf-8')

COUNT = 1
while COUNT:
  # time.sleep(2)
  try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    ssock = context.wrap_socket(sock, server_hostname="localhost")
    ssock.connect((IP, PORT))
    print(ssock.version())
    # ssock.send("Hello, World!".encode())
    ssock.send("pathname,someone,someone,1".encode())
    response = ssock.recv(1024)
    print(len(response),end=' ')
    dec = decrypt(response)
    print(dec)
    ssock.shutdown(socket.SHUT_RDWR)
  except Exception as e:
    # pass
    print("\n",response)
    print(e)
  finally:
    ssock.close()
    COUNT -= 1
    time.sleep(0.5)
